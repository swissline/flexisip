/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2010-2015  Belledonne Communications SARL, All rights reserved.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <iomanip>
#include <sstream>

#include <assert.h>
#include <regex.h>

#include <bctoolbox/crypto.h>
#include <sofia-sip/auth_plugin.h>
#include <sofia-sip/msg_addr.h>
#include <sofia-sip/nua.h>
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>
#include <sofia-sip/su_tagarg.h>

#include "agent.hh"

#include "module-auth.hh"

using namespace std;

// ====================================================================================================================
//  NonceStore class
// ====================================================================================================================

int NonceStore::getNc(const string &nonce) {
	unique_lock<mutex> lck(mMutex);
	auto it = mNc.find(nonce);
	if (it != mNc.end())
		return (*it).second.nc;
	return -1;
}

void NonceStore::insert(msg_header_t *response) {
	const char *nonce = msg_header_find_param((msg_common_t const *)response, "nonce");
	string snonce(nonce);
	snonce = snonce.substr(1, snonce.length() - 2);
	LOGD("New nonce %s", snonce.c_str());
	insert(snonce);
}

void NonceStore::insert(const string &nonce) {
	unique_lock<mutex> lck(mMutex);
	time_t expiration = getCurrentTime() + mNonceExpires;
	auto it = mNc.find(nonce);
	if (it != mNc.end()) {
		LOGE("Replacing nonce count for %s", nonce.c_str());
		it->second.nc = 0;
		it->second.expires = expiration;
	} else {
		mNc.insert(make_pair(nonce, NonceCount(0, expiration)));
	}
}

void NonceStore::updateNc(const string &nonce, int newnc) {
	unique_lock<mutex> lck(mMutex);
	auto it = mNc.find(nonce);
	if (it != mNc.end()) {
		LOGD("Updating nonce %s with nc=%d", nonce.c_str(), newnc);
		(*it).second.nc = newnc;
	} else {
		LOGE("Couldn't update nonce %s: not found", nonce.c_str());
	}
}

void NonceStore::erase(const string &nonce) {
	unique_lock<mutex> lck(mMutex);
	LOGD("Erasing nonce %s", nonce.c_str());
	mNc.erase(nonce);
}

void NonceStore::cleanExpired() {
	unique_lock<mutex> lck(mMutex);
	int count = 0;
	time_t now = getCurrentTime();
	size_t size = 0;
	for (auto it = mNc.begin(); it != mNc.end();) {
		if (now > it->second.expires) {
			LOGD("Cleaning expired nonce %s", it->first.c_str());
			auto eraseIt = it;
			++it;
			mNc.erase(eraseIt);
			++count;
		} else
			++it;
		size++;
	}
	if (count)
		LOGD("Cleaned %d expired nonces, %zd remaining", count, size);
}

// ====================================================================================================================

// ====================================================================================================================
//  OdbcAuthModule class
// ====================================================================================================================

OdbcAuthModule::OdbcAuthModule(su_root_t *root, const std::string &domain, const std::string &algo):
	AuthModule(root,
		AUTHTAG_REALM(domain.c_str()),
		AUTHTAG_OPAQUE("+GNywA=="),
		AUTHTAG_FORBIDDEN(1),
		AUTHTAG_ALLOW("ACK CANCEL BYE"),
		AUTHTAG_ALGORITHM(algo.c_str()),
		TAG_END()
	),
	mDisableQOPAuth(true) {
}

OdbcAuthModule::OdbcAuthModule(su_root_t *root, const std::string &domain, const std::string &algo, int nonceExpire):
	AuthModule(root,
		AUTHTAG_REALM(domain.c_str()),
		AUTHTAG_OPAQUE("+GNywA=="),
		AUTHTAG_FORBIDDEN(1),
		AUTHTAG_ALLOW("ACK CANCEL BYE"),
		AUTHTAG_ALGORITHM(algo.c_str()),
		AUTHTAG_EXPIRES(nonceExpire),
		AUTHTAG_NEXT_EXPIRES(nonceExpire),
		TAG_END()
	) {
	mNonceStore.setNonceExpires(nonceExpire);
}

void OdbcAuthModule::onCheck(AuthStatus &as, msg_auth_t *au, auth_challenger_t const *ach) {
	auto &authStatus = dynamic_cast<OdbcAuthStatus &>(as);
	AuthenticationListener &listener = authStatus.listener();
	listener.setData(*this, authStatus, ach);

	as.allow(as.allow() || auth_allow_check(mAm, as.getPtr()) == 0);

	if (as.realm()) {
		/* Workaround for old linphone client that don't check whether algorithm is MD5 or SHA256.
		 * They then answer for both, but the first one for SHA256 is of course wrong.
		 * We workaround by selecting the second digest response.
		 */
		if (au && au->au_next) {
			auth_response_t r;
			memset(&r, 0, sizeof(r));
			r.ar_size = sizeof(r);
			auth_digest_response_get(as.home(), &r, au->au_next->au_params);

			if (r.ar_algorithm == NULL || !strcasecmp(r.ar_algorithm, "MD5")) {
				au = au->au_next;
			}
		}
		/* After auth_digest_credentials, there is no more au->au_next. */
		au = auth_digest_credentials(au, as.realm(), mAm->am_opaque);
	} else
		au = NULL;

	if (as.allow()) {
		LOGD("%s: allow unauthenticated %s", __func__, as.method());
		as.status(0), as.phrase(nullptr);
		as.match(reinterpret_cast<msg_header_t *>(au));
		return;
	}

	if (au) {
		SLOGD << "Searching for auth digest response for this proxy";
		msg_auth_t *matched_au = ModuleToolbox::findAuthorizationForRealm(as.home(), au, as.realm());
		if (matched_au)
			au = matched_au;
		auth_digest_response_get(as.home(), &listener.mAr, au->au_params);
		SLOGD << "Using auth digest response for realm " << listener.mAr.ar_realm;
		as.match(reinterpret_cast<msg_header_t *>(au));
		flexisip_auth_check_digest(as, &listener.mAr, ach);
	} else {
		/* There was no realm or credentials, send challenge */
		SLOGD << __func__ << ": no credentials matched realm or no realm";
		auth_challenge_digest(mAm, as.getPtr(), ach);
		mNonceStore.insert(as.response());

		// Retrieve the password in the hope it will be in cache when the remote UAC
		// sends back its request; this time with the expected authentication credentials.
		if (mImmediateRetrievePass) {
			SLOGD << "Searching for " << as.userUri()->url_user
			<< " password to have it when the authenticated request comes";
			AuthDbBackend::get()->getPassword(as.userUri()->url_user, as.userUri()->url_host, as.userUri()->url_user, nullptr);
			//AuthDbBackend::get()->getPasswordForAlgo(as->as_user_uri->url_user, as->as_user_uri->url_host, as->as_user_uri->url_user, NULL, listener);
		}
		listener.finish();
		return;
	}
}

void OdbcAuthModule::onChallenge(AuthStatus &as, auth_challenger_t const *ach) {
	auth_challenge_digest(mAm, as.getPtr(), ach);
}

void OdbcAuthModule::onCancel(AuthStatus &as) {
	auth_cancel_default(mAm, as.getPtr());
}

#define PA "Authorization missing "

/** Verify digest authentication */
void OdbcAuthModule::flexisip_auth_check_digest(AuthStatus &as, auth_response_t *ar, auth_challenger_t const *ach) {
	AuthenticationListener &listener = dynamic_cast<OdbcAuthStatus &>(as).listener();

	if (ar == NULL || ach == NULL) {
		as.status(500);
		as.phrase("Internal Server Error");
		as.response(nullptr);
		listener.finish();
		return;
	}

	char const *phrase = "Bad authorization ";
	if ((!ar->ar_username && (phrase = PA "username")) || (!ar->ar_nonce && (phrase = PA "nonce")) ||
		(!mDisableQOPAuth && !ar->ar_nc && (phrase = PA "nonce count")) ||
		(!ar->ar_uri && (phrase = PA "URI")) || (!ar->ar_response && (phrase = PA "response")) ||
		/* (!ar->ar_opaque && (phrase = PA "opaque")) || */
		/* Check for qop */
		(ar->ar_qop &&
		((ar->ar_auth && !strcasecmp(ar->ar_qop, "auth") && !strcasecmp(ar->ar_qop, "\"auth\"")) ||
		(ar->ar_auth_int && !strcasecmp(ar->ar_qop, "auth-int") && !strcasecmp(ar->ar_qop, "\"auth-int\""))) &&
		(phrase = PA "has invalid qop"))) {

		// assert(phrase);
		LOGD("auth_method_digest: 400 %s", phrase);
		as.status(400);
		as.phrase(phrase);
		as.response(nullptr);
		listener.finish();
		return;
	}

	if (!ar->ar_username || !as.userUri()->url_user || !ar->ar_realm || !as.userUri()->url_host) {
		as.status(403);
		as.phrase("Authentication info missing");
		SLOGUE << "Registration failure, authentication info are missing: usernames " <<
		ar->ar_username << "/" << as.userUri()->url_user << ", hosts " << ar->ar_realm << "/" << as.userUri()->url_host;
		LOGD("from and authentication usernames [%s/%s] or from and authentication hosts [%s/%s] empty",
				ar->ar_username, as.userUri()->url_user, ar->ar_realm, as.userUri()->url_host);
		as.response(nullptr);
		listener.finish();
		return;
	}

	msg_time_t now = msg_now();
	if (as.nonceIssued() == 0 /* Already validated nonce */ && auth_validate_digest_nonce(mAm, as.getPtr(), ar, now) < 0) {
		as.blacklist(mAm->am_blacklist);
		auth_challenge_digest(mAm, as.getPtr(), ach);
		mNonceStore.insert(as.response());
		listener.finish();
		return;
	}

	if (as.stale()) {
		auth_challenge_digest(mAm, as.getPtr(), ach);
		mNonceStore.insert(as.response());
		listener.finish();
		return;
	}

	if (!mDisableQOPAuth) {
		int pnc = mNonceStore.getNc(ar->ar_nonce);
		int nnc = (int)strtoul(ar->ar_nc, NULL, 16);
		if (pnc == -1 || pnc >= nnc) {
			LOGE("Bad nonce count %d -> %d for %s", pnc, nnc, ar->ar_nonce);
			as.blacklist(mAm->am_blacklist);
			auth_challenge_digest(mAm, as.getPtr(), ach);
			mNonceStore.insert(as.response());
			listener.finish();
			return;
		} else {
			mNonceStore.updateNc(ar->ar_nonce, nnc);
		}
	}

	AuthDbBackend::get()->getPassword(as.userUri()->url_user, as.userUri()->url_host, ar->ar_username, &listener);
}

// ====================================================================================================================

// ====================================================================================================================
//  Authentication::AuthenticationListener class
// ====================================================================================================================

AuthenticationListener::AuthenticationListener(Authentication *module, shared_ptr<RequestSipEvent> ev) : mModule(module), mEv(ev) {
	memset(&mAr, '\0', sizeof(mAr));
	mAr.ar_size = sizeof(mAr);
}

void AuthenticationListener::setData(OdbcAuthModule &am, OdbcAuthStatus &as, auth_challenger_t const *ach) {
	mAm = &am;
	mAs = &as;
	mAch = ach;
}

void AuthenticationListener::main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u) {
	AuthenticationListener **listenerStorage = (AuthenticationListener **)su_msg_data(msg);
	AuthenticationListener *listener = *listenerStorage;
	listener->processResponse();
}

void AuthenticationListener::onResult(AuthDbResult result, const vector<passwd_algo_t> &passwd) {
	// invoke callback on main thread (sofia-sip)
	su_msg_r mamc = SU_MSG_R_INIT;
	if (-1 == su_msg_create(mamc, su_root_task(getRoot()), su_root_task(getRoot()), main_thread_async_response_cb,
		sizeof(AuthenticationListener *))) {
		LOGF("Couldn't create auth async message");
		}

		string algo = "";
	AuthenticationListener **listenerStorage = (AuthenticationListener **)su_msg_data(mamc);
	*listenerStorage = this;

	switch (result) {
		case PASSWORD_FOUND:
			mResult = AuthDbResult::PASSWORD_FOUND;

			if (mAr.ar_algorithm == NULL || !strcmp(mAr.ar_algorithm, "MD5")) {
				algo = "MD5";
			} else if (!strcmp(mAr.ar_algorithm, "SHA-256")) {
				algo = "SHA-256";
			} else {
				mResult = AuthDbResult::AUTH_ERROR;
				break;
			}

			for (const auto &password : passwd) {
				if (password.algo == algo) mPassword = password.pass;
			}

			if (mPassword.empty()) {
				mResult = AuthDbResult::PASSWORD_NOT_FOUND;
			}

			break;
		case PASSWORD_NOT_FOUND:
			mResult = AuthDbResult::PASSWORD_NOT_FOUND;
			mPassword = "";
			break;
		case AUTH_ERROR:
			/*in that case we can fallback to the cached password previously set*/
			break;
		case PENDING:
			LOGF("unhandled case PENDING");
			break;
	}
	if (-1 == su_msg_send(mamc)) {
		LOGF("Couldn't send auth async message to main thread.");
	}
}

void AuthenticationListener::onResult(AuthDbResult result, const string &passwd) {
	// invoke callback on main thread (sofia-sip)
	su_msg_r mamc = SU_MSG_R_INIT;
	if (-1 == su_msg_create(mamc, su_root_task(getRoot()), su_root_task(getRoot()), main_thread_async_response_cb,
		sizeof(AuthenticationListener *))) {
		LOGF("Couldn't create auth async message");
		}

		AuthenticationListener **listenerStorage = (AuthenticationListener **)su_msg_data(mamc);
	*listenerStorage = this;

	switch (result) {
		case PASSWORD_FOUND:
			mResult = AuthDbResult::PASSWORD_FOUND;
			mPassword = passwd;
			break;
		case PASSWORD_NOT_FOUND:
			mResult = AuthDbResult::PASSWORD_NOT_FOUND;
			mPassword = "";
			break;
		case AUTH_ERROR:
			/*in that case we can fallback to the cached password previously set*/
			break;
		case PENDING:
			LOGF("unhandled case PENDING");
			break;
	}
	if (-1 == su_msg_send(mamc)) {
		LOGF("Couldn't send auth async message to main thread.");
	}
}

void AuthenticationListener::finishForAlgorithm () {
	if ((mAs->usedAlgo().size() > 1) && (mAs->status() == 401)) {
		msg_header_t* response = msg_header_copy(mAs->home(), mAs->response());
		msg_header_remove_param((msg_common_t *)response, "algorithm=MD5");
		msg_header_replace_item(mAs->home(), (msg_common_t *)response, "algorithm=SHA-256");
		mEv->reply(mAs->status(), mAs->phrase(), SIPTAG_HEADER((const sip_header_t *)mAs->info()),
				   SIPTAG_HEADER((const sip_header_t *)response),
				   SIPTAG_HEADER((const sip_header_t *)mAs->response()),
				   SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	} else {
		mEv->reply(mAs->status(), mAs->phrase(), SIPTAG_HEADER((const sip_header_t *)mAs->info()),
				   SIPTAG_HEADER((const sip_header_t *)mAs->response()),
				   SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
	}
}

/**
 * return true if the event is terminated
 */
void AuthenticationListener::finish() {
	const shared_ptr<MsgSip> &ms = mEv->getMsgSip();
	const sip_t *sip = ms->getSip();
	if (mAs->status()) {
		if (mAs->status() != 401 && mAs->status() != 407) {
			auto log = make_shared<AuthLog>(sip, mPasswordFound);
			log->setStatusCode(mAs->status(), mAs->phrase());
			log->setCompleted();
			mEv->setEventLog(log);
		}
		finishForAlgorithm();
	} else {
		// Success
		if (sip->sip_request->rq_method == sip_method_register) {
			msg_auth_t *au =
			ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_authorization, mAs->realm());
			if (au)
				msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		} else {
			msg_auth_t *au = ModuleToolbox::findAuthorizationForRealm(ms->getHome(), sip->sip_proxy_authorization, mAs->realm());
			if(au->au_next)
				msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au->au_next);
			if (au)
				msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		}
		if (mEv->isSuspended()) {
			// The event is re-injected
			getAgent()->injectRequestEvent(mEv);
		}
	}
	if (mModule->mCurrentAuthOp == this) {
		mModule->mCurrentAuthOp = NULL;
	}
	delete this;
}

void AuthenticationListener::finishVerifyAlgos(const vector<passwd_algo_t> &pass) {
	mAs->usedAlgo().remove_if([&pass](string algo) {
		bool found = false;

		for (const auto &password : pass) {
			if (password.algo == algo) {
				found = true;
				break;
			}
		}

		return !found;
	});

	finish();
}

Agent *AuthenticationListener::getAgent() const {
	return mModule->getAgent();
}

int AuthenticationListener::checkPasswordMd5(const char *passwd){
	char const *a1;
	auth_hexmd5_t a1buf, response;

	if (passwd && passwd[0] == '\0')
		passwd = NULL;

	if (passwd) {
		mPasswordFound = true;
		++*getModule()->mCountPassFound;
		strncpy(a1buf, passwd, 33); // remove trailing NULL character
		a1 = a1buf;
	} else {
		++*getModule()->mCountPassNotFound;
		auth_digest_a1(&mAr, a1buf, "xyzzy"), a1 = a1buf;
	}

	if (mAr.ar_md5sess)
		auth_digest_a1sess(&mAr, a1buf, a1), a1 = a1buf;

	auth_digest_response(&mAr, response, a1, mAs->method(), mAs->body(), mAs->bodyLen());
	return !passwd || strcmp(response, mAr.ar_response);
}

int AuthenticationListener::checkPasswordForAlgorithm(const char *passwd) {
	if ((mAr.ar_algorithm == NULL) || (!strcmp(mAr.ar_algorithm, "MD5"))) {
		return checkPasswordMd5(passwd);
	} else if (!strcmp(mAr.ar_algorithm, "SHA-256")) {
		if (passwd && passwd[0] == '\0')
			passwd = NULL;

		string a1;
		if (passwd) {
			mPasswordFound = true;
			++*getModule()->mCountPassFound;
			a1 = passwd;
		} else {
			++*getModule()->mCountPassNotFound;
			a1 = auth_digest_a1_for_algorithm(&mAr, "xyzzy");
		}

		if (mAr.ar_md5sess)
			a1 = auth_digest_a1sess_for_algorithm(&mAr, a1);

		string response = auth_digest_response_for_algorithm(&mAr, mAs->method(), mAs->body(), mAs->bodyLen(), a1);
		return (passwd && response == mAr.ar_response ? 0 : -1);
	}
	return -1;
}

/**
 * NULL if passwd not found.
 */
void AuthenticationListener::checkPassword(const char *passwd) {
	if (checkPasswordForAlgorithm(passwd)) {
		if (mAm->getPtr()->am_forbidden && !mAs->no403()) {
			mAs->status(403);
			mAs->phrase("Forbidden");
			mAs->response(nullptr);
			mAs->blacklist(mAm->getPtr()->am_blacklist);
		} else {
			auth_challenge_digest(mAm->getPtr(), mAs->getPtr(), mAch);
			mAm->nonceStore().insert(mAs->response());
			mAs->blacklist(mAm->getPtr()->am_blacklist);
		}
		if (passwd) {
			SLOGUE << "Registration failure, password did not match";
			LOGD("auth_method_digest: password '%s' did not match", passwd);
		} else {
			SLOGUE << "Registration failure, no password";
			LOGD("auth_method_digest: no password");
		}

		return;
	}

	// assert(apw);
	mAs->user(mAr.ar_username);
	mAs->anonymous(false);

	if (mAm->getPtr()->am_nextnonce || mAm->getPtr()->am_mutual)
		auth_info_digest(mAm->getPtr(), mAs->getPtr(), mAch);

	if (mAm->getPtr()->am_challenge)
		auth_challenge_digest(mAm->getPtr(), mAs->getPtr(), mAch);

	LOGD("auth_method_digest: successful authentication");

	mAs->status(0); /* Successful authentication! */
	mAs->phrase("");
}

void AuthenticationListener::processResponse() {
	switch (mResult) {
		case PASSWORD_FOUND:
		case PASSWORD_NOT_FOUND:
			checkPassword(mPassword.c_str());
			finish();
			break;
		case AUTH_ERROR:
			onError();
			break;
		default:
			LOGE("Unhandled asynchronous response %u", mResult);
			onError();
	}
}

void AuthenticationListener::onError() {
	if (mAs->status() != 0) {
		mAs->status(500);
		mAs->phrase("Internal error");
		mAs->response(nullptr);
	}
	finish();
}

std::string AuthenticationListener::sha256(const std::string &data) {
	const size_t hashLen = 32;
	vector<uint8_t> hash(hashLen);
	bctbx_sha256(reinterpret_cast<const uint8_t *>(data.c_str()), data.size(), hash.size(), hash.data());
	return toString(hash);
}

std::string AuthenticationListener::sha256(const void *data, size_t len) {
	const size_t hashLen = 32;
	vector<uint8_t> hash(hashLen);
	bctbx_sha256(reinterpret_cast<const uint8_t *>(data), len, hash.size(), hash.data());
	return toString(hash);
}

std::string AuthenticationListener::toString(const std::vector<uint8_t> &data) {
	ostringstream out;
	out.str().reserve(data.size() * 2);
	out << hex << setfill('0') << setw(2);
	for (const uint8_t &byte : data) {
		out << unsigned(byte);
	}
	return out.str();
}

std::string AuthenticationListener::auth_digest_a1_for_algorithm(const ::auth_response_t *ar, const std::string &secret) {
	ostringstream data;
	data << ar->ar_username << ':' << ar->ar_realm << ':' << secret;
	string ha1 = sha256(data.str());
	SLOGD << "auth_digest_ha1() has A1 = SHA256(" << ar->ar_username << ':' << ar->ar_realm << ":*******) = " << ha1 << endl;
	return ha1;
}

std::string AuthenticationListener::auth_digest_a1sess_for_algorithm(const ::auth_response_t *ar, const std::string &ha1) {
	ostringstream data;
	data << ha1 << ':' << ar->ar_nonce << ':' << ar->ar_cnonce;
	string newHa1 = sha256(data.str());
	SLOGD << "auth_sessionkey has A1' = SHA256(" << data.str() << ") = " << newHa1 << endl;
	return newHa1;
}

std::string AuthenticationListener::auth_digest_response_for_algorithm(
	::auth_response_t *ar,
	char const *method_name,
	void const *data,
	isize_t dlen,
	const std::string &ha1
) {
	if (ar->ar_auth_int)
		ar->ar_qop = "auth-int";
	else if (ar->ar_auth)
		ar->ar_qop = "auth";
	else
		ar->ar_qop = NULL;

	/* Calculate Hentity */
	string Hentity;
	if (ar->ar_auth_int) {
		if (data && dlen) {
			Hentity = sha256(data, dlen);
		} else {
			Hentity = "d7580069de562f5c7fd932cc986472669122da91a0f72f30ef1b20ad6e4f61a3";
		}
	}

	/* Calculate A2 */
	ostringstream input;
	if (ar->ar_auth_int) {
		input << method_name << ':' << ar->ar_uri << ':' << Hentity;
	} else
		input << method_name << ':' << ar->ar_uri;
	string ha2 = sha256(input.str());
	LOGD("A2 = SHA256(%s:%s%s%s)\n", method_name, ar->ar_uri,
		 ar->ar_auth_int ? ":" : "", ar->ar_auth_int ? Hentity.c_str() : "");

	/* Calculate response */
	ostringstream input2;
	input2 << ha1 << ':' << ar->ar_nonce << ':' << ar->ar_nc << ':' << ar->ar_cnonce << ':' << ar->ar_qop << ':' << ha2;
	string response = sha256(input2.str());
	LOGD("auth_response: %s = SHA256(%s:%s%s%s%s%s%s%s:%s) (qop=%s)\n",
		response.c_str(), ha1.c_str(), ar->ar_nonce,
		ar->ar_auth ||  ar->ar_auth_int ? ":" : "",
		ar->ar_auth ||  ar->ar_auth_int ? ar->ar_nc : "",
		ar->ar_auth ||  ar->ar_auth_int ? ":" : "",
		ar->ar_auth ||  ar->ar_auth_int ? ar->ar_cnonce : "",
		ar->ar_auth ||  ar->ar_auth_int ? ":" : "",
		ar->ar_auth ||  ar->ar_auth_int ? ar->ar_qop : "",
		ha2.c_str(),
		ar->ar_qop ? ar->ar_qop : "NONE"
	);

	return response;
}

// ====================================================================================================================


// ====================================================================================================================
//  Authentication class
// ====================================================================================================================

Authentication::Authentication(Agent *ag) : Module(ag) {
	mProxyChallenger.ach_status = 407; /*SIP_407_PROXY_AUTH_REQUIRED*/
	mProxyChallenger.ach_phrase = sip_407_Proxy_auth_required;
	mProxyChallenger.ach_header = sip_proxy_authenticate_class;
	mProxyChallenger.ach_info = sip_proxy_authentication_info_class;

	mRegistrarChallenger.ach_status = 401; /*SIP_401_UNAUTHORIZED*/
	mRegistrarChallenger.ach_phrase = sip_401_Unauthorized;
	mRegistrarChallenger.ach_header = sip_www_authenticate_class;
	mRegistrarChallenger.ach_info = sip_authentication_info_class;
}

Authentication::~Authentication() {
	if (mRequiredSubjectCheckSet){
		regfree(&mRequiredSubject);
	}
}

void Authentication::onDeclare(GenericStruct *mc) {
	ConfigItemDescriptor items[] = {
		{StringList, "auth-domains", "List of whitespace separated domain names to challenge. Others are denied.", "localhost"},
		{StringList, "trusted-hosts", "List of whitespace separated IP which will not be challenged.", ""},
		{String, "db-implementation", "Database backend implementation for digest authentication [odbc,soci,file].", "file"},
		{String, "datasource",
			"Odbc connection string to use for connecting to database. "
			"ex1: DSN=myodbc3; where 'myodbc3' is the datasource name. "
			"ex2: DRIVER={MySQL};SERVER=host;DATABASE=db;USER=user;PASSWORD=pass;OPTION=3; for a DSN-less connection. "
			"ex3: /etc/flexisip/passwd; for a file containing user credentials in clear-text, md5 or sha256. "
			"The file must start with 'version:1' as the first line, and then contains lines in the form of:\n"
			"user@domain clrtxt:clear-text-password md5:md5-password sha256:sha256-password ;\n"
			"For example: \n"
			"bellesip@sip.linphone.org clrtxt:secret ;\n"
			"bellesip@sip.linphone.org md5:97ffb1c6af18e5687bf26cdf35e45d30 ;\n"
			"bellesip@sip.linphone.org clrtxt:secret md5:97ffb1c6af18e5687bf26cdf35e45d30 sha256:d7580069de562f5c7fd932cc986472669122da91a0f72f30ef1b20ad6e4f61a3 ;",
			""
		},
		{Integer, "nonce-expires", "Expiration time of nonces, in seconds.", "3600"},
		{Integer, "cache-expire", "Duration of the validity of the credentials added to the cache in seconds.", "1800"},
		{Boolean, "hashed-passwords",
			"True if retrieved passwords from the database are hashed. HA1=MD5(A1) = MD5(username:realm:pass).",
			"false"
		},
		{BooleanExpr, "no-403", "Don't reply 403, but 401 or 407 even in case of wrong authentication.", "false"},
		{Boolean, "reject-wrong-client-certificates",
			"If set to true, the module will simply reject with 403 forbidden any request coming from client"
			" who presented a bad TLS certificate (regardless of reason: improper signature, unmatched subjects)."
			" Otherwise, the module will fallback to a digest authentication.\n"
			"This policy applies only for transports configured with 'required-peer-certificate=1' parameter; indeed"
			" no certificate is requested to the client otherwise.",
			"false"
		},
		{String, "tls-client-certificate-required-subject", "An optional regular expression matched against subjects of presented"
			" client certificates. If this regular expression evaluates to false, the request is rejected. "
			"The matched subjects are, in order: subjectAltNames.DNS, subjectAltNames.URI, subjectAltNames.IP and CN.",
			""
		},
		{Boolean, "new-auth-on-407", "When receiving a proxy authenticate challenge, generate a new challenge for this proxy.", "false"},
		{Boolean, "enable-test-accounts-creation",
			"Enable a feature useful for automatic tests, allowing a client to create a temporary account in the "
			"password database in memory."
			"This MUST not be used for production as it is a real security hole.",
			"false"
		},
		{Boolean, "disable-qop-auth",
			"Disable the QOP authentication method. Default is to use it, use this flag to disable it if needed.",
			"false"
		},
		/* We need this configuration because of old client that do not support multiple Authorization.
			* When a user have a clear text password, it will be hashed into md5 and sha256.
			* This will force the use of only the algorithm supported by them.
			*/
		{StringList, "available-algorithms",
			"List of algorithms, separated by whitespaces (valid values are MD5 and SHA-256).\n"
			"This feature allows to force the use of wanted algorithm(s).\n"
			"If the value is empty, then it will authorize all implemented algorithms.",
			"MD5"
		},
		{StringList, "trusted-client-certificates", "List of whitespace separated username or username@domain CN "
			"which will trusted. If no domain is given it is computed.",
			""
		},
		{Boolean, "trust-domain-certificates",
			"If enabled, all requests which have their request URI containing a trusted domain will be accepted.",
			"false"
		},
		config_item_end
	};

	mc->addChildrenValues(items);
	/* modify the default value for "enabled" */
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
	mc->get<ConfigBoolean>("hashed-passwords")->setDeprecated(true);
	//we deprecate "trusted-client-certificates" because "tls-client-certificate-required-subject" can do more.
	mc->get<ConfigStringList>("trusted-client-certificates")->setDeprecated(true);

	// Call declareConfig for backends
	AuthDbBackend::declareConfig(mc);

	mCountAsyncRetrieve = mc->createStat("count-async-retrieve", "Number of asynchronous retrieves.");
	mCountSyncRetrieve = mc->createStat("count-sync-retrieve", "Number of synchronous retrieves.");
	mCountPassFound = mc->createStat("count-password-found", "Number of passwords found.");
	mCountPassNotFound = mc->createStat("count-password-not-found", "Number of passwords not found.");
}

void Authentication::onLoad(const GenericStruct *mc) {
	mDomains = mc->get<ConfigStringList>("auth-domains")->read();
	loadTrustedHosts(*mc->get<ConfigStringList>("trusted-hosts"));
	mNewAuthOn407 = mc->get<ConfigBoolean>("new-auth-on-407")->read();
	mTrustedClientCertificates = mc->get<ConfigStringList>("trusted-client-certificates")->read();
	mTrustDomainCertificates = mc->get<ConfigBoolean>("trust-domain-certificates")->read();
	mNo403Expr = mc->get<ConfigBooleanExpression>("no-403")->read();
	mTestAccountsEnabled = mc->get<ConfigBoolean>("enable-test-accounts-creation")->read();
	mDisableQOPAuth = mc->get<ConfigBoolean>("disable-qop-auth")->read();
	int nonceExpires = mc->get<ConfigInt>("nonce-expires")->read();
	mAlgorithms = mc->get<ConfigStringList>("available-algorithms")->read();
	mAlgorithms.unique();

	for (auto it = mAlgorithms.begin(); it != mAlgorithms.end();) {
		if ((*it != "MD5") && (*it != "SHA-256")) {
			SLOGW << "Given algorithm '" << *it << "' is not valid. Must be either MD5 or SHA-256.";
			it = mAlgorithms.erase(it);
		} else {
			it++;
		}
	}

	if (mAlgorithms.empty()) {
		mAlgorithms.push_back("MD5");
		mAlgorithms.push_back("SHA-256");
	}

	for (const string &domain : mDomains) {
		if (mDisableQOPAuth) {
			mAuthModules[domain].reset(new OdbcAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front()));
		} else {
			mAuthModules[domain].reset(new OdbcAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front(), nonceExpires));
		}
		SLOGI << "Found auth domain: " << domain;
	}

	string requiredSubject = mc->get<ConfigString>("tls-client-certificate-required-subject")->read();
	if (!requiredSubject.empty()){
		int res = regcomp(&mRequiredSubject, requiredSubject.c_str(),  REG_EXTENDED|REG_NOSUB);
		if (res != 0) {
			string err_msg(128,0);
			regerror(res, &mRequiredSubject, &err_msg[0], err_msg.capacity());
			LOGF("Could not compile regex for 'tls-client-certificate-required-subject' '%s': %s", requiredSubject.c_str(), err_msg.c_str());
		}else mRequiredSubjectCheckSet = true;
	}
	mRejectWrongClientCertificates = mc->get<ConfigBoolean>("reject-wrong-client-certificates")->read();
	AuthDbBackend::get();//force instanciation of the AuthDbBackend NOW, to force errors to arrive now if any.
}

OdbcAuthModule *Authentication::findAuthModule(const string name) {
	auto it = mAuthModules.find(name);
	if (it == mAuthModules.end())
		it = mAuthModules.find("*");
	if (it == mAuthModules.end()) {
		for (auto it2 = mAuthModules.begin(); it2 != mAuthModules.end(); ++it2) {
			string domainName = it2->first;
			size_t wildcardPosition = domainName.find("*");
			// if domain has a wildcard in it, try to match
			if (wildcardPosition != string::npos) {
				size_t beforeWildcard = name.find(domainName.substr(0, wildcardPosition));
				size_t afterWildcard = name.find(domainName.substr(wildcardPosition + 1));
				if (beforeWildcard != string::npos && afterWildcard != string::npos) {
					return it2->second.get();
				}
			}
		}
	}
	if (it == mAuthModules.end()) {
		return nullptr;
	}
	return it->second.get();
}

bool Authentication::containsDomain(const list<string> &d, const char *name) {
	return find(d.cbegin(), d.cend(), "*") != d.end() || find(d.cbegin(), d.cend(), name) != d.end();
}

bool Authentication::handleTestAccountCreationRequests(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();
	if (sip->sip_request->rq_method == sip_method_register) {
		sip_unknown_t *h = ModuleToolbox::getCustomHeaderByName(sip, "X-Create-Account");
		if (h && strcasecmp(h->un_value, "yes") == 0) {
			url_t *url = sip->sip_from->a_url;
			if (url) {
				sip_unknown_t *h2 = ModuleToolbox::getCustomHeaderByName(sip, "X-Phone-Alias");
				const char* phone_alias = h2 ? h2->un_value : NULL;
				phone_alias = phone_alias ? phone_alias : "";
				AuthDbBackend::get()->createAccount(url->url_user, url->url_host, url->url_user, url->url_password,
													sip->sip_expires->ex_delta, phone_alias);
				LOGD("Account created for %s@%s with password %s and expires %lu%s%s", url->url_user, url->url_host,
					 url->url_password, sip->sip_expires->ex_delta, phone_alias ? " with phone alias " : "", phone_alias);
				return true;
			}
		}
	}
	return false;
}

bool Authentication::isTrustedPeer(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();

	// Check for trusted host
	sip_via_t *via = sip->sip_via;
	list<BinaryIp>::const_iterator trustedHostsIt = mTrustedHosts.begin();
	const char *printableReceivedHost = !empty(via->v_received) ? via->v_received : via->v_host;

	BinaryIp receivedHost(printableReceivedHost, true);

	for (; trustedHostsIt != mTrustedHosts.end(); ++trustedHostsIt) {
		if (receivedHost == *trustedHostsIt) {
			LOGD("Allowing message from trusted host %s", printableReceivedHost);
			return true;
		}
	}
	return false;
}

bool Authentication::tlsClientCertificatePostCheck(const shared_ptr<RequestSipEvent> &ev){
	if (mRequiredSubjectCheckSet){
		bool ret = ev->matchIncomingSubject(&mRequiredSubject);
		if (ret){
			SLOGD<<"TLS certificate postcheck successful.";
		}else{
			SLOGUE<<"TLS certificate postcheck failed.";
		}
		return ret;
	}
	return true;
}

/* This function returns
 * true: if the tls authentication is handled (either successful or rejected)
 * false: if we have to fallback to digest
 */
bool Authentication::handleTlsClientAuthentication(shared_ptr<RequestSipEvent> &ev) {
	sip_t *sip = ev->getSip();
	shared_ptr<tport_t> inTport = ev->getIncomingTport();
	unsigned int policy = 0;

	tport_get_params(inTport.get(), TPTAG_TLS_VERIFY_POLICY_REF(policy), NULL);
	// Check TLS certificate
	if ((policy & TPTLS_VERIFY_INCOMING) && tport_is_server(inTport.get())){
		/* tls client certificate is required for this transport*/
		if (tport_is_verified(inTport.get())) {
			/*the certificate looks good, now match subjects*/
			const url_t *from = sip->sip_from->a_url;
			const char *fromDomain = from->url_host;
			const char *res = NULL;
			url_t searched_uri = URL_INIT_AS(sip);
			SofiaAutoHome home;
			char *searched;

			searched_uri.url_host = from->url_host;
			searched_uri.url_user = from->url_user;
			searched = url_as_string(home.home(), &searched_uri);

			if (ev->findIncomingSubject(searched)) {
				SLOGD << "Allowing message from matching TLS certificate";
				goto postcheck;
			} else if (sip->sip_request->rq_method != sip_method_register &&
				(res = findIncomingSubjectInTrusted(ev, fromDomain))) {
				SLOGD << "Found trusted TLS certificate " << res;
			goto postcheck;
				} else {
					/*case where the certificate would work for the entire domain*/
					searched_uri.url_user = NULL;
					searched = url_as_string(home.home(), &searched_uri);
					if (ev->findIncomingSubject(searched)) {
						SLOGD << "Found TLS certificate for entire domain";
						goto postcheck;
					}
				}

				if (sip->sip_request->rq_method != sip_method_register && mTrustDomainCertificates) {
					searched_uri.url_user = NULL;
					searched_uri.url_host = sip->sip_request->rq_url->url_host;
					searched = url_as_string(home.home(), &searched_uri);
					if (ev->findIncomingSubject(searched)) {
						SLOGD << "Found trusted TLS certificate for the request URI domain";
						goto postcheck;
					}
				}

				LOGE("Client is presenting a TLS certificate not matching its identity.");
				SLOGUE << "Registration failure for " << url_as_string(home.home(), from) << ", TLS certificate doesn't match its identity";
				goto bad_certificate;

				postcheck:
				if (tlsClientCertificatePostCheck(ev)){
					/*all is good, return true*/
					return true;
				}else goto bad_certificate;
		}else goto bad_certificate;

		bad_certificate:
		if (mRejectWrongClientCertificates){
			ev->reply(403, "Bad tls client certificate", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
			return true; /*the request is responded, no further processing required*/
		}
		/*fallback to digest*/
		return false;
	}
	/*no client certificate requested, go to digest auth*/
	return false;
}

void Authentication::onRequest(shared_ptr<RequestSipEvent> &ev) {
	const shared_ptr<MsgSip> &ms = ev->getMsgSip();
	sip_t *sip = ms->getSip();
	sip_p_preferred_identity_t *ppi = NULL;

	// Do it first to make sure no transaction is created which
	// would send an unappropriate 100 trying response.
	if (sip->sip_request->rq_method == sip_method_ack || sip->sip_request->rq_method == sip_method_cancel ||
		sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
	) {
		/*ack and cancel shall never be challenged according to the RFC.*/
		return;
	}

	// handle account creation request (test feature only)
	if (mTestAccountsEnabled && handleTestAccountCreationRequests(ev)) {
		ev->reply(200, "Test account created", SIPTAG_SERVER_STR(getAgent()->getServerString()), SIPTAG_CONTACT(sip->sip_contact), SIPTAG_EXPIRES_STR("0"), TAG_END());
		return;
	}

	// Check trusted peer
	if (isTrustedPeer(ev))
		return;

	// Check for auth module for this domain, this will also tell us if this domain is allowed (auth-domains config
	// item)
	const char *fromDomain = sip->sip_from->a_url[0].url_host;
	if (fromDomain && strcmp(fromDomain, "anonymous.invalid") == 0) {
		ppi = sip_p_preferred_identity(sip);
		if (ppi)
			fromDomain = ppi->ppid_url->url_host;
		else
			LOGD("There is no p-preferred-identity");
	}

	OdbcAuthModule *am = findAuthModule(fromDomain);
	if (am == NULL) {
		LOGI("Unknown domain [%s]", fromDomain);
		SLOGUE << "Registration failure, domain is forbidden: " << fromDomain;
		ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// check if TLS client certificate provides sufficent authentication for this request.
	if (handleTlsClientAuthentication(ev))
		return;

	// Check for the existence of username, which is required for proceeding with digest authentication in flexisip.
	// Reject if absent.
	if (sip->sip_from->a_url->url_user == NULL) {
		LOGI("From has no username, cannot authenticate.");
		SLOGUE << "Registration failure, username not found: " << url_as_string(ms->getHome(), sip->sip_from->a_url);
		ev->reply(403, "Username must be provided", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
		return;
	}

	// Create incoming transaction if not already exists
	// Necessary in qop=auth to prevent nonce count chaos
	// with retransmissions.
	ev->createIncomingTransaction();

	auto *as = new OdbcAuthStatus();
	as->method(sip->sip_request->rq_method_name);
	as->source(msg_addrinfo(ms->getMsg()));
	as->userUri(ppi ? ppi->ppid_url : sip->sip_from->a_url);
	as->realm(as->userUri()->url_host);
	as->display(sip->sip_from->a_display);
	if (sip->sip_payload) {
		as->body(sip->sip_payload->pl_data);
		as->bodyLen(sip->sip_payload->pl_len);
	}
	as->no403(mNo403Expr->eval(ev->getSip()));
	as->usedAlgo() = mAlgorithms;
	as->listener(new AuthenticationListener(this, ev));

	// Attention: the auth_mod_verify method should not send by itself any message but
	// return after having set the as status and phrase.
	// Another point in asynchronous mode is that the asynchronous callbacks MUST be called
	// AFTER the nta_msg_treply bellow. Otherwise the as would be already destroyed.
	if (sip->sip_request->rq_method == sip_method_register) {
		am->verify(*as, sip->sip_authorization, &mRegistrarChallenger);
	} else {
		am->verify(*as, sip->sip_proxy_authorization, &mProxyChallenger);
	}
	if (mCurrentAuthOp) {
		/*it has not been cleared by the listener itself, so password checking is still in progress. We need to
		 * suspend the event*/
		// Send pending message, needed data will be kept as long
		// as SipEvent is held in the listener.
		ev->suspendProcessing();
	}
}

void Authentication::onResponse(shared_ptr<ResponseSipEvent> &ev) {
	if (!mNewAuthOn407) return; /*nop*/

	shared_ptr<OutgoingTransaction> transaction = dynamic_pointer_cast<OutgoingTransaction>(ev->getOutgoingAgent());
	if (transaction == NULL) return;

	shared_ptr<string> proxyRealm = transaction->getProperty<string>("this_proxy_realm");
	if (proxyRealm == NULL) return;

	sip_t *sip = ev->getMsgSip()->getSip();
	if (sip->sip_status->st_status == 407 && sip->sip_proxy_authenticate) {
		auto *as = new OdbcAuthStatus();
		as->realm(proxyRealm.get()->c_str());
		as->userUri(sip->sip_from->a_url);
		OdbcAuthModule *am = findAuthModule(as->realm());
		if (am) {
			am->challenge(*as, &mProxyChallenger);
			am->nonceStore().insert(as->response());
			msg_header_insert(ev->getMsgSip()->getMsg(), (msg_pub_t *)sip, (msg_header_t *)as->response());
		} else {
			LOGD("Authentication module for %s not found", as->realm());
		}
	} else {
		LOGD("not handled newauthon401");
	}
}

void Authentication::onIdle() {
	for (auto &it : mAuthModules) {
		it.second->nonceStore().cleanExpired();
	}
}

bool Authentication::doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) {
	if (conf.getName() == "trusted-hosts" && state == ConfigState::Commited) {
		loadTrustedHosts((const ConfigStringList &)conf);
		LOGD("Trusted hosts updated");
		return true;
	} else {
		return Module::doOnConfigStateChanged(conf, state);
	}
}

const char *Authentication::findIncomingSubjectInTrusted(shared_ptr<RequestSipEvent> &ev, const char *fromDomain) {
	if (mTrustedClientCertificates.empty())
		return NULL;
	list<string> toCheck;
	for (auto it = mTrustedClientCertificates.cbegin(); it != mTrustedClientCertificates.cend(); ++it) {
		if (it->find("@") != string::npos)
			toCheck.push_back(*it);
		else
			toCheck.push_back(*it + "@" + string(fromDomain));
	}
	const char *res = ev->findIncomingSubject(toCheck);
	return res;
}

void Authentication::loadTrustedHosts(const ConfigStringList &trustedHosts) {
	list<string> hosts = trustedHosts.read();
	transform(hosts.begin(), hosts.end(), back_inserter(mTrustedHosts), [](string host) {
		return BinaryIp(host.c_str());
	});

	const GenericStruct *clusterSection = GenericManager::get()->getRoot()->get<GenericStruct>("cluster");
	bool clusterEnabled = clusterSection->get<ConfigBoolean>("enabled")->read();
	if (clusterEnabled) {
		list<string> clusterNodes = clusterSection->get<ConfigStringList>("nodes")->read();
		for (list<string>::const_iterator node = clusterNodes.cbegin(); node != clusterNodes.cend(); node++) {
			BinaryIp nodeIp((*node).c_str());

			if (find(mTrustedHosts.cbegin(), mTrustedHosts.cend(), nodeIp) == mTrustedHosts.cend()) {
				mTrustedHosts.push_back(nodeIp);
			}
		}
	}

	const GenericStruct *presenceSection = GenericManager::get()->getRoot()->get<GenericStruct>("module::Presence");
	bool presenceServer = presenceSection->get<ConfigBoolean>("enabled")->read();
	if (presenceServer) {
		SofiaAutoHome home;
		string presenceServer = presenceSection->get<ConfigString>("presence-server")->read();
		sip_contact_t *contact = sip_contact_make(home.home(), presenceServer.c_str());
		url_t *url = contact ? contact->m_url : NULL;
		if (url && url->url_host) {
			BinaryIp host(url->url_host);

			if (find(mTrustedHosts.cbegin(), mTrustedHosts.cend(), host) == mTrustedHosts.cend()) {
				SLOGI << "Adding presence server '" << url->url_host << "' to trusted hosts";
				mTrustedHosts.push_back(host);
			}
		} else {
			SLOGW << "Could not parse presence server URL '" << presenceServer << "', cannot be added to trusted hosts!";
		}
	}
}

ModuleInfo<Authentication> Authentication::sInfo(
	"Authentication",
	"The authentication module challenges and authenticates SIP requests using two possible methods: \n"
	" * if the request is received via a TLS transport and 'require-peer-certificate' is set in transport definition "
	"in [Global] section for this transport, "
	" then the From header of the request is matched with the CN claimed by the client certificate. The CN must "
	"contain sip:user@domain or alternate name with URI=sip:user@domain"
	" corresponding to the URI in the from header for the request to be accepted. Optionnaly, the property"
	" tls-client-certificate-required-subject may contain a regular expression for additional checks to execute on certificate subjects.\n"
	" * if no TLS client based authentication can be performed, or is failed, then a SIP digest authentication is "
	"performed. The password verification is made by querying"
	" a database or a password file on disk.",
	{ "NatHelper" },
	ModuleInfoBase::ModuleOid::Authentication
);

// ====================================================================================================================
