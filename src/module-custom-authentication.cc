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

#include "module-custom-authentication.hh"

using namespace std;

std::ostream &operator<<(std::ostream &os, const http_payload_t *httpPayload) {
	const http_payload_t *httpPayloadBase = reinterpret_cast<const http_payload_t *>(httpPayload);
	if (httpPayload->pl_data) {
		os.write(reinterpret_cast<const char *>(httpPayloadBase->pl_data), httpPayloadBase->pl_len);
	}
	return os;
}

void ModuleCustomAuthentication::onDeclare(GenericStruct *mc) {
	ConfigItemDescriptor items[] = {
		{ String, "remote-auth-uri", "", "" },
		config_item_end
	};
	mc->addChildrenValues(items);
	mc->get<ConfigBoolean>("enabled")->setDefault("false");
}

void ModuleCustomAuthentication::onLoad(const GenericStruct *root) {
	mEngine = nth_engine_create(mAgent->getRoot(), TAG_END());
	mUriFormater.setTemplate(root->get<ConfigString>("remote-auth-uri")->read());
}

void ModuleCustomAuthentication::onUnload() {
	nth_engine_destroy(mEngine);
	mEngine = nullptr;
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

		map<string, string> params = extractParameters(*ms);
		string uri = mUriFormater.format(params);

		nth_client_t *request = nth_client_tcreate(mEngine,
			onHttpResponseCb,
			reinterpret_cast<nth_client_magic_t *>(this),
			http_method_get,
			"GET",
			URL_STRING_MAKE(uri.c_str()),
			TAG_END()
		);
		if (request == nullptr) {
			ostringstream os;
			os << "HTTP request for '" << uri << "' has failed";
			throw runtime_error(os.str());
		}

		SLOGD << "HTTP request [" << request << "] to '" << uri << "' successfully sent";
		addPendingEvent(request, ev);
		ev->suspendProcessing();
	} catch (const runtime_error &e) {
		SLOGE << e.what();
		ev->reply(500, "Internal error", TAG_END());
	}
}

void ModuleCustomAuthentication::onHttpResponse(nth_client_t *request, const http_t *http) {
	shared_ptr<RequestSipEvent> ev;
	try {
		int sipCode = 0;
		string reasonStr;

		ev = removePendingEvent(request);

		if (http == nullptr) {
			ostringstream os;
			os << "HTTP server responds with code " << nth_client_status(request);
			throw runtime_error(os.str());
		}

		int status = http->http_status->st_status;
		SLOGD << "HTTP response received [" << status << "]: " << endl << http->http_payload;
		if (status != 200) {
			ostringstream os;
			os << "unhandled HTTP status code [" << status << "]";
			throw runtime_error(os.str());
		}

		string httpBody = toString(http->http_payload);
		if (httpBody.empty()) {
			ostringstream os;
			os << "HTTP server answered with an empty body";
			throw runtime_error(os.str());
		}

		istringstream is(httpBody);
		is >> sipCode >> reasonStr;
		if (!validSipCode(sipCode) || reasonStr.empty()) {
			ostringstream os;
			os << "invalid SIP code or reason (sipCode=" << sipCode << "), (reason='" << reasonStr << "')";
			throw runtime_error(os.str());
		}

		if (sipCode == 200) {
			getAgent()->injectRequestEvent(ev);
		} else {
			ev->reply(sipCode, reasonStr.c_str(), TAG_END());
		}
	} catch (const logic_error &e) { // thrown by removePendingEvent()
		SLOGE << e.what();
	} catch (const runtime_error &e) {
		SLOGE << "HTTP request [" << request << "]: " << e.what();
		ev->reply(500, "Internal error", TAG_END());
	}
}

void ModuleCustomAuthentication::addPendingEvent(nth_client_t *request, const std::shared_ptr<RequestSipEvent> &ev) {
	shared_ptr<RequestSipEvent> &evRef = mPendingEvent[request];
	if (evRef) {
		ostringstream os;
		os << request << " HTTP request is already pending";
		mPendingEvent.erase(request);
		throw logic_error(os.str());
	}
	evRef = ev;
}

std::shared_ptr<RequestSipEvent> ModuleCustomAuthentication::removePendingEvent(nth_client_t *request) {
	auto it = mPendingEvent.find(request);
	if (it == mPendingEvent.end()) {
		ostringstream os;
		os << "HTTP request (" << request << ") doesn't exist in pending requests list";
		throw logic_error(os.str());
	}
	shared_ptr<RequestSipEvent> ev = it->second;
	mPendingEvent.erase(it);
	return ev;
}

std::map<std::string, std::string> ModuleCustomAuthentication::extractParameters(const MsgSip &msg) const {
	map<string, string> params;
	sip_auth_t *authHeader = msg.getSip()->sip_authorization ? msg.getSip()->sip_authorization : msg.getSip()->sip_proxy_authorization;
	if (authHeader) {
		try {
			params = splitCommaSeparatedKeyValuesList(*authHeader->au_params);
			params["scheme"] = authHeader->au_scheme;
		} catch (const invalid_argument &e) { // thrown by splitCommaSeparatedKeyValuesList()
			ostringstream os;
			os << "failed to extract parameters from '" << *authHeader->au_params << "': " << e.what();
			throw runtime_error(os.str());
		}
	}
	return params;
}

std::map<std::string, std::string> ModuleCustomAuthentication::splitCommaSeparatedKeyValuesList(const std::string &kvList) const {
	map<string, string> keyValues;
	string::const_iterator keyPos = kvList.cbegin();
	while (keyPos != kvList.cend()) {
		auto commaPos = find(keyPos, kvList.cend(), ',');
		auto eqPos = find(keyPos, commaPos, '=');
		if (eqPos == commaPos) {
			ostringstream os;
			os << "invalid key-value: '" << string(keyPos, commaPos) << "'";
			throw invalid_argument(os.str());
		}
		string key(keyPos, eqPos);
		string value(eqPos+1, commaPos);
		if (key.empty() || value.empty()) {
			ostringstream os;
			os << "empty key or value: '" << string(keyPos, commaPos) << "'";
			throw invalid_argument(os.str());
		}
		keyValues[move(key)] = move(value);
		keyPos = commaPos != kvList.cend() ? commaPos+1 : kvList.cend();
	}
	return keyValues;
}

int ModuleCustomAuthentication::onHttpResponseCb(nth_client_magic_t *magic, nth_client_t *request, const http_t *http) {
	try {
		reinterpret_cast<ModuleCustomAuthentication *>(magic)->onHttpResponse(request, http);
	} catch (...) {}
	return 0;
}

std::string ModuleCustomAuthentication::toString(const http_payload_t *httpPayload) {
	if (httpPayload == nullptr || httpPayload->pl_data == nullptr || httpPayload->pl_len == 0) {
		return string();
	}
	return string(httpPayload->pl_data, httpPayload->pl_len);
}

bool ModuleCustomAuthentication::validSipCode(int sipCode) {
	const auto it = find(mValidSipCodes.cbegin(), mValidSipCodes.cend(), sipCode);
	return (it != mValidSipCodes.cend());
}

std::array<int, 4> ModuleCustomAuthentication::mValidSipCodes = {200, 401, 407, 403};

ModuleInfo<ModuleCustomAuthentication> ModuleCustomAuthentication::mModuleInfo(
	"CustomAuthentication",
	"Ask an HTTP server for authentication",
	{ "Authentication" },
	ModuleInfoBase::ModuleOid::CustomAuthentication
);
