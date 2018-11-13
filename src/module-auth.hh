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

#include "authdb.hh"
#include "module.hh"

class NonceStore {
public:
	NonceStore() : mNonceExpires(3600) {}
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
	int mNonceExpires;
};

class Authentication : public Module {
public:
	StatCounter64 *mCountAsyncRetrieve;
	StatCounter64 *mCountSyncRetrieve;
	StatCounter64 *mCountPassFound;
	StatCounter64 *mCountPassNotFound;
	NonceStore mNonceStore;

	Authentication(Agent *ag);
	~Authentication();

	virtual void onDeclare(GenericStruct *mc);
	void onLoad(const GenericStruct *mc);
	auth_mod_t *findAuthModule(const std::string name);
	auth_mod_t *createAuthModule(const std::string &domain, int nonceExpires);
	static bool containsDomain(const std::list<std::string> &d, const char *name);
	bool handleTestAccountCreationRequests(std::shared_ptr<RequestSipEvent> &ev);
	bool isTrustedPeer(std::shared_ptr<RequestSipEvent> &ev);
	bool tlsClientCertificatePostCheck(const std::shared_ptr<RequestSipEvent> &ev);
	bool handleTlsClientAuthentication(std::shared_ptr<RequestSipEvent> &ev);
	void onRequest(std::shared_ptr<RequestSipEvent> &ev);
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev);
	void onIdle() {mNonceStore.cleanExpired();}
	virtual bool doOnConfigStateChanged(const ConfigValue &conf, ConfigState state);

private:
	class AuthenticationListener : public AuthDbListener {
	public:
		bool mImmediateRetrievePass;
		bool mNo403;
		std::list<std::string> mAlgoUsed;
		auth_response_t mAr;

		AuthenticationListener(Authentication *, std::shared_ptr<RequestSipEvent>);
		virtual ~AuthenticationListener() = default;

		void setData(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach);
		void checkPassword(const char *password);
		int checkPasswordMd5(const char *password);
		int checkPasswordForAlgorithm(const char *password);
		void onResult(AuthDbResult result, const std::string &passwd);
		void onResult(AuthDbResult result, const std::vector<passwd_algo_t> &passwd);
		void onError();
		void finish(); /*the listener is destroyed when calling this, careful*/
		void finishForAlgorithm();
		void finishVerifyAlgos(const std::vector<passwd_algo_t> &pass);

		su_root_t *getRoot() {return getAgent()->getRoot();}
		Agent *getAgent() {return mModule->getAgent();}
		Authentication *getModule() {return mModule;}

	private:
		void processResponse();
		static void main_thread_async_response_cb(su_root_magic_t *rm, su_msg_r msg, void *u);
		static std::string sha256(const std::string &data);
		static std::string sha256(const void *data, size_t len);
		static std::string toString(const std::vector<uint8_t> &data);
		static std::string auth_digest_a1_for_algorithm(const auth_response_t *ar, const std::string &secret);
		static std::string auth_digest_a1sess_for_algorithm(const auth_response_t *ar, const std::string &ha1);
		static std::string auth_digest_response_for_algorithm(::auth_response_t *ar, char const *method_name, void const *data, isize_t dlen, const std::string &ha1);

		friend class Authentication;
		Authentication *mModule;
		std::shared_ptr<RequestSipEvent> mEv;
		auth_mod_t *mAm;
		auth_status_t *mAs;
		auth_challenger_t const *mAch;
		bool mPasswordFound;
		AuthDbResult mResult;
		std::string mPassword;
	};

	static int authPluginInit(auth_mod_t *am, auth_scheme_t *base, su_root_t *root, tag_type_t tag, tag_value_t value, ...);
	bool empty(const char *value) {return value == NULL || value[0] == '\0';}
	void static flexisip_auth_method_digest(auth_mod_t *am, auth_status_t *as, msg_auth_t *au, auth_challenger_t const *ach);
	void static flexisip_auth_check_digest(auth_mod_t *am, auth_status_t *as, auth_response_t *ar, auth_challenger_t const *ach);
	const char *findIncomingSubjectInTrusted(std::shared_ptr<RequestSipEvent> &ev, const char *fromDomain);
	void loadTrustedHosts(const ConfigStringList &trustedHosts);
	const GenericStruct *presenceSection = GenericManager::get()->getRoot()->get<GenericStruct>("module::Presence");

	static ModuleInfo<Authentication> sInfo;
	std::map<std::string, auth_mod_t *> mAuthModules;
	std::list<std::string> mDomains;
	std::list<BinaryIp> mTrustedHosts;
	std::list<std::string> mTrustedClientCertificates;
	std::list<std::string> mAlgorithms;

	regex_t mRequiredSubject;
	auth_challenger_t mRegistrarChallenger;
	auth_challenger_t mProxyChallenger;
	auth_scheme_t *mOdbcAuthScheme;
	std::shared_ptr<BooleanExpression> mNo403Expr;
	AuthenticationListener *mCurrentAuthOp;
	bool mImmediateRetrievePassword;
	bool mNewAuthOn407;
	bool mTestAccountsEnabled;
	bool mDisableQOPAuth;
	bool mRequiredSubjectCheckSet;
	bool mRejectWrongClientCertificates;
	bool mTrustDomainCertificates;
};
