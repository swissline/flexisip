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

#pragma once

#include <ctime>
#include <list>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <sofia-sip/msg_types.h>

#include "auth/auth-module.hh"
#include "authdb.hh"
#include "module.hh"

class NonceStore {
public:
	void setNonceExpires(int value) {mNonceExpires = value;}
	int getNc(const std::string &nonce);
	void insert(msg_header_t *response);
	void insert(const std::string &nonce);
	void updateNc(const std::string &nonce, int newnc);
	void erase(const std::string &nonce);
	void cleanExpired();

private:
	struct NonceCount {
		NonceCount(int c, time_t ex) : nc(c), expires(ex) {
		}
		int nc;
		std::time_t expires;
	};

	std::map<std::string, NonceCount> mNc;
	std::mutex mMutex;
	int mNonceExpires = 3600;
};

class AuthenticationListener;

class OdbcAuthStatus : public AuthStatus {
public:
	OdbcAuthStatus(): AuthStatus() {}

	bool no403() const {return mNo403;}
	void no403(bool no403) {mNo403 = no403;}

	bool passwordFound() const {return mPasswordFound;}
	void passwordFound(bool val) {mPasswordFound = val;}

	std::list<std::string> &usedAlgo() {return mAlgoUsed;}

private:
	std::list<std::string> mAlgoUsed;
	std::shared_ptr<RequestSipEvent> mEvent;
	bool mNo403 = false;
	bool mPasswordFound = false;
};

class OdbcAuthModule : public AuthModule {
public:
	OdbcAuthModule(su_root_t *root, const std::string &domain, const std::string &algo);
	OdbcAuthModule(su_root_t *root, const std::string &domain, const std::string &algo, int nonceExpire);
	~OdbcAuthModule() override = default;

	NonceStore &nonceStore() {return mNonceStore;}

private:
	void onCheck(AuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) override;
	void onChallenge(AuthStatus &as, auth_challenger_t const *ach) override;
	void onCancel(AuthStatus &as) override;

	void flexisip_auth_check_digest(OdbcAuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach);
	void finish(OdbcAuthStatus &as);
	void processResponse(AuthenticationListener &listener);
	void checkPassword(OdbcAuthStatus &as, const auth_challenger_t &ach, auth_response_t &ar, const char *password);
	int checkPasswordForAlgorithm(OdbcAuthStatus &as, auth_response_t &ar, const char *password);
	int checkPasswordMd5(OdbcAuthStatus &as, auth_response_t &ar, const char *passwd);
	void onError(OdbcAuthStatus &as);

	static std::string auth_digest_a1_for_algorithm(const auth_response_t *ar, const std::string &secret);
	static std::string auth_digest_a1sess_for_algorithm(const auth_response_t *ar, const std::string &ha1);
	static std::string auth_digest_response_for_algorithm(::auth_response_t *ar, char const *method_name, void const *data, isize_t dlen, const std::string &ha1);
	static std::string sha256(const std::string &data);
	static std::string sha256(const void *data, size_t len);
	static std::string toString(const std::vector<uint8_t> &data);

	NonceStore mNonceStore;
	bool mDisableQOPAuth = false;
	bool mImmediateRetrievePass = true;

	friend AuthenticationListener;
};

class Authentication;

class AuthenticationListener : public AuthDbListener {
public:
	AuthenticationListener(OdbcAuthModule &am, OdbcAuthStatus &as, const auth_challenger_t &ach, const auth_response_t &ar): mAm(am), mAs(as), mAch(ach), mAr(ar) {}
	~AuthenticationListener() override = default;

	OdbcAuthStatus &authStatus() const {return mAs;}
	const auth_challenger_t &challenger() const {return mAch;}
	auth_response_t *response() {return &mAr;}

	std::string password() const {return mPassword;}
	AuthDbResult result() const {return mResult;}

	void onResult(AuthDbResult result, const std::string &passwd) override;
	void onResult(AuthDbResult result, const std::vector<passwd_algo_t> &passwd) override;
	void finishVerifyAlgos(const std::vector<passwd_algo_t> &pass) override;

private:
	static void main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u);

	friend class Authentication;
	OdbcAuthModule &mAm;
	OdbcAuthStatus &mAs;
	const auth_challenger_t &mAch;
	auth_response_t mAr;
	AuthDbResult mResult;
	std::string mPassword;
};

class Authentication : public Module {
public:
	StatCounter64 *mCountAsyncRetrieve = nullptr;
	StatCounter64 *mCountSyncRetrieve = nullptr;
	StatCounter64 *mCountPassFound = nullptr;
	StatCounter64 *mCountPassNotFound = nullptr;

	Authentication(Agent *ag);
	~Authentication() override;

	void onDeclare(GenericStruct *mc) override;
	void onLoad(const GenericStruct *mc) override;
	OdbcAuthModule *findAuthModule(const std::string name);
	static bool containsDomain(const std::list<std::string> &d, const char *name);
	bool handleTestAccountCreationRequests(std::shared_ptr<RequestSipEvent> &ev);
	bool isTrustedPeer(std::shared_ptr<RequestSipEvent> &ev);
	bool tlsClientCertificatePostCheck(const std::shared_ptr<RequestSipEvent> &ev);
	bool handleTlsClientAuthentication(std::shared_ptr<RequestSipEvent> &ev);
	void onRequest(std::shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override;
	void onIdle() override;
	bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state) override;

private:
	class RequestAuthStatus : public OdbcAuthStatus {
	public:
		RequestAuthStatus(const std::shared_ptr<RequestSipEvent> &ev): OdbcAuthStatus(), mEv(ev) {}
		~RequestAuthStatus() override = default;

		const std::shared_ptr<RequestSipEvent> &getRequestEvent() const {return mEv;}

	private:
		std::shared_ptr<RequestSipEvent> mEv;
	};

	void processAuthModuleResponse(AuthStatus &as);
	bool empty(const char *value) {return value == NULL || value[0] == '\0';}
	const char *findIncomingSubjectInTrusted(std::shared_ptr<RequestSipEvent> &ev, const char *fromDomain);
	void loadTrustedHosts(const ConfigStringList &trustedHosts);

	static ModuleInfo<Authentication> sInfo;
	std::map<std::string, std::unique_ptr<OdbcAuthModule>> mAuthModules;
	std::map<std::unique_ptr<AuthStatus>, std::shared_ptr<RequestSipEvent>> mPendingAuths;
	std::list<std::string> mDomains;
	std::list<BinaryIp> mTrustedHosts;
	std::list<std::string> mTrustedClientCertificates;
	std::list<std::string> mAlgorithms;

	regex_t mRequiredSubject;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	std::shared_ptr<BooleanExpression> mNo403Expr;
	AuthenticationListener *mCurrentAuthOp = nullptr;
	bool mNewAuthOn407 = false;
	bool mTestAccountsEnabled = false;
	bool mDisableQOPAuth = false;
	bool mRequiredSubjectCheckSet = false;
	bool mRejectWrongClientCertificates = false;
	bool mTrustDomainCertificates = false;

	friend AuthenticationListener;
};
