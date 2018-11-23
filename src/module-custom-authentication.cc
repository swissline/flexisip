/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.

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

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include <sofia-sip/msg_addr.h>
#include <sofia-sip/sip_extra.h>
#include <sofia-sip/sip_status.h>

#include "module-custom-authentication.hh"

using namespace std;

std::ostream &operator<<(std::ostream &os, const http_payload_t *httpPayload) {
	const http_payload_t *httpPayloadBase = reinterpret_cast<const http_payload_t *>(httpPayload);
	if (httpPayload->pl_data) {
		os.write(reinterpret_cast<const char *>(httpPayloadBase->pl_data), httpPayloadBase->pl_len);
	}
	return os;
}

ModuleCustomAuthentication::ModuleCustomAuthentication(Agent *agent) : Module(agent) {
	mProxyChallenger.ach_status = 407; /*SIP_407_PROXY_AUTH_REQUIRED*/
	mProxyChallenger.ach_phrase = sip_407_Proxy_auth_required;
	mProxyChallenger.ach_header = sip_proxy_authenticate_class;
	mProxyChallenger.ach_info = sip_proxy_authentication_info_class;

	mRegistrarChallenger.ach_status = 401; /*SIP_401_UNAUTHORIZED*/
	mRegistrarChallenger.ach_phrase = sip_401_Unauthorized;
	mRegistrarChallenger.ach_header = sip_www_authenticate_class;
	mRegistrarChallenger.ach_info = sip_authentication_info_class;
}

void ModuleCustomAuthentication::onDeclare(GenericStruct *mc) {
	ConfigItemDescriptor items[] = {
		{ StringList, "auth-domains", "", "localhost" },
		{ String, "remote-auth-uri", "", "" },
		{ StringList, "available-algorithms", "", "MD5" },
		{ Boolean, "disable-qop-auth", "", "false" },
		{ Integer, "nonce-expires", "", "3600" },
		config_item_end
	};
	mc->addChildrenValues(items);
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
}

void ModuleCustomAuthentication::onLoad(const GenericStruct *mc) {
	list<string> authDomains = mc->get<ConfigStringList>("auth-domains")->read();

	list<string> mAlgorithms = mc->get<ConfigStringList>("available-algorithms")->read();
	if (mAlgorithms.empty()) mAlgorithms = {"MD5", "SHA-256"};
	mAlgorithms.unique();

	bool disableQOPAuth = mc->get<ConfigBoolean>("disable-qop-auth")->read();
	int nonceExpires = mc->get<ConfigInt>("nonce-expires")->read();

	for (const string &domain : authDomains) {
		unique_ptr<HttpAuthModule> am;
		if (disableQOPAuth) {
			am.reset(new HttpAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front()));
		} else {
			am.reset(new HttpAuthModule(getAgent()->getRoot(), domain, mAlgorithms.front(), nonceExpires));
		}
		am->getFormater().setTemplate(mc->get<ConfigString>("remote-auth-uri")->read());
		mAuthModules[domain] = move(am);
	}
}

void ModuleCustomAuthentication::onRequest(std::shared_ptr<RequestSipEvent> &ev) {
	try {
		const shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();

		// Do it first to make sure no transaction is created which
		// would send an inappropriate 100 trying response.
		if (sip->sip_request->rq_method == sip_method_ack || sip->sip_request->rq_method == sip_method_cancel ||
			sip->sip_request->rq_method == sip_method_bye // same as in the sofia auth modules
		) {
			/*ack and cancel shall never be challenged according to the RFC.*/
			return;
		}

		sip_p_preferred_identity_t *ppi = nullptr;
		const char *fromDomain = sip->sip_from->a_url[0].url_host;
		if (fromDomain && strcmp(fromDomain, "anonymous.invalid") == 0) {
			ppi = sip_p_preferred_identity(sip);
			if (ppi)
				fromDomain = ppi->ppid_url->url_host;
			else
				LOGD("There is no p-preferred-identity");
		}

		HttpAuthModule *am = findAuthModule(fromDomain);
		if (am == nullptr) {
			SLOGI << "Unknown domain [" << fromDomain << "]";
			SLOGUE << "Registration failure, domain is forbidden: " << fromDomain;
			ev->reply(403, "Domain forbidden", SIPTAG_SERVER_STR(getAgent()->getServerString()), TAG_END());
			return;
		}

		auto *as = new _AuthStatus(ev);
		as->method(sip->sip_request->rq_method_name);
		as->source(msg_addrinfo(ms->getMsg()));
		as->userUri(ppi ? ppi->ppid_url : sip->sip_from->a_url);
		as->realm(as->userUri()->url_host);
		as->display(sip->sip_from->a_display);
		if (sip->sip_payload) {
			as->body(sip->sip_payload->pl_data);
			as->bodyLen(sip->sip_payload->pl_len);
		}
		as->usedAlgo() = mAlgorithms;

		if (sip->sip_request->rq_method == sip_method_register) {
			am->verify(*as, sip->sip_authorization, &mRegistrarChallenger);
		} else {
			am->verify(*as, sip->sip_proxy_authorization, &mProxyChallenger);
		}

		processAuthModuleResponse(*as);
	} catch (const runtime_error &e) {
		SLOGE << e.what();
		ev->reply(500, "Internal error", TAG_END());
	}
}

HttpAuthModule *ModuleCustomAuthentication::findAuthModule(const std::string name) {
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

void ModuleCustomAuthentication::processAuthModuleResponse(AuthStatus &as) {
	const shared_ptr<RequestSipEvent> &ev = dynamic_cast<const _AuthStatus &>(as).event();
	auto &authStatus = dynamic_cast<_AuthStatus &>(as);
	if (as.status() == 0) {
		const std::shared_ptr<MsgSip> &ms = ev->getMsgSip();
		sip_t *sip = ms->getSip();
		if (sip->sip_request->rq_method == sip_method_register) {
			msg_auth_t *au = ModuleToolbox::findAuthorizationForRealm(
				ms->getHome(),
				sip->sip_authorization,
				as.realm()
			);
			if (au) msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		} else {
			msg_auth_t *au = ModuleToolbox::findAuthorizationForRealm(
				ms->getHome(),
				sip->sip_proxy_authorization,
				as.realm()
			);
			if (au->au_next) msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au->au_next);
			if (au) msg_header_remove(ms->getMsg(), (msg_pub_t *)sip, (msg_header_t *)au);
		}
		if (ev->isSuspended()) {
			// The event is re-injected
			getAgent()->injectRequestEvent(ev);
		}
	} else if (as.status() == 100) {
		using std::placeholders::_1;
		ev->suspendProcessing();
		as.callback(std::bind(&ModuleCustomAuthentication::processAuthModuleResponse, this, _1));
		return;
	} else if (as.status() >= 400) {
		if (as.status() == 401 || as.status() == 407) {
			auto log = make_shared<AuthLog>(ev->getMsgSip()->getSip(), authStatus.passwordFound());
			log->setStatusCode(as.status(), as.phrase());
			log->setCompleted();
			ev->setEventLog(log);
		}
		ev->reply(as.status(), as.phrase(),
			SIPTAG_HEADER((const sip_header_t *)as.info()),
			SIPTAG_HEADER((const sip_header_t *)as.response()),
			SIPTAG_SERVER_STR(getAgent()->getServerString()),
			TAG_END()
		);
	} else {
		ev->reply(500, "Internal error", TAG_END());
	}
	delete &as;
}

ModuleInfo<ModuleCustomAuthentication> ModuleCustomAuthentication::mModuleInfo(
	"CustomAuthentication",
	"Ask an HTTP server for authentication",
	{ "Authentication" },
	ModuleInfoBase::ModuleOid::CustomAuthentication
);
