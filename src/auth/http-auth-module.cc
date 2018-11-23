/*
 * Flexisip, a flexible SIP proxy server with media capabilities.
 * Copyright (C) 2018  Belledonne Communications SARL, All rights reserved.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include "log/logmanager.hh"

#include "http-auth-module.hh"

using namespace std;

HttpAuthModule::HttpAuthModule(su_root_t *root, const std::string &domain, const std::string &algo) : FlexisipAuthModuleBase(root, domain, algo) {
	mEngine = nth_engine_create(root, TAG_END());
}

HttpAuthModule::HttpAuthModule(su_root_t *root, const std::string &domain, const std::string &algo, int nonceExpire) : FlexisipAuthModuleBase(root, domain, algo, nonceExpire) {
	mEngine = nth_engine_create(root, TAG_END());
}

HttpAuthModule::~HttpAuthModule() {
	nth_engine_destroy(mEngine);
}

void HttpAuthModule::checkAuthHeader(FlexisipAuthStatus &as, msg_auth_t *credentials, auth_challenger_t const *ach) {
	try {
		map<string, string> params = extractParameters(*credentials);
		string uri = mUriFormater.format(params);

		auto *ctx = new pair<HttpAuthModule &, FlexisipAuthStatus &>(*this, as);

		nth_client_t *request = nth_client_tcreate(mEngine,
			onHttpResponseCb,
			reinterpret_cast<nth_client_magic_t *>(ctx),
			http_method_get,
			"GET",
			URL_STRING_MAKE(uri.c_str()),
			TAG_END()
		);
		if (request == nullptr) {
			ostringstream os;
			os << "HTTP request for '" << uri << "' has failed";
			delete ctx;
			throw runtime_error(os.str());
		}

		SLOGD << "HTTP request [" << request << "] to '" << uri << "' successfully sent";
	} catch (const runtime_error &e) {
		SLOGE << e.what();
		onError(as);
	}
}

void HttpAuthModule::loadPassword(const FlexisipAuthStatus &as) {
}

std::map<std::string, std::string> HttpAuthModule::extractParameters(const msg_auth_t &credentials) const {
	map<string, string> params;
	try {
		params = splitCommaSeparatedKeyValuesList(*credentials.au_params);
		params["scheme"] = credentials.au_scheme;
	} catch (const invalid_argument &e) { // thrown by splitCommaSeparatedKeyValuesList()
		ostringstream os;
		os << "failed to extract parameters from '" << *credentials.au_params << "': " << e.what();
		throw runtime_error(os.str());
	}
	return params;
}

std::map<std::string, std::string> HttpAuthModule::splitCommaSeparatedKeyValuesList(const std::string &kvList) const {
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

void HttpAuthModule::onHttpResponse(FlexisipAuthStatus &as, nth_client_t *request, const http_t *http) {
	shared_ptr<RequestSipEvent> ev;
	try {
		int sipCode = 0;
		string reasonHeaderValue;
		ostringstream os;

		if (http == nullptr) {
			os << "HTTP server responds with code " << nth_client_status(request);
			throw runtime_error(os.str());
		}

		int status = http->http_status->st_status;
		SLOGD << "HTTP response received [" << status << "]: " << endl << http->http_payload;
		if (status != 200) {
			os << "unhandled HTTP status code [" << status << "]";
			throw runtime_error(os.str());
		}

		string httpBody = toString(http->http_payload);
		if (httpBody.empty()) {
			os << "HTTP server answered with an empty body";
			throw runtime_error(os.str());
		}

		try {
			map<string, string> kv = parseHttpBody(httpBody);
			sipCode = stoi(kv["Status"]);
			reasonHeaderValue = move(kv["Reason"]);
		} catch (const logic_error &e) {
			os << "error while parsing HTTP body: " << e.what();
			throw runtime_error(os.str());
		}

		if (!validSipCode(sipCode) || reasonHeaderValue.empty()) {
			os << "invlaid SIP code or reason";
			throw runtime_error(os.str());
		}

		auto &httpAuthStatus = dynamic_cast<HttpAuthModule::Status &>(as);
		httpAuthStatus.status(sipCode);
		httpAuthStatus.phrase("");
		httpAuthStatus.reason(reasonHeaderValue);
	} catch (const runtime_error &e) {
		SLOGE << "HTTP request [" << request << "]: " << e.what();
		onError(as);
	}
	finish(as);
}

std::map<std::string, std::string> HttpAuthModule::parseHttpBody(const std::string &body) const {
	istringstream is(body);
	ostringstream os;
	map<string, string> result;
	string line;

	do {
		getline(is, line);
		if (line.empty()) continue;

		auto column = find(line.cbegin(), line.cend(), ':');
		if (column == line.cend()) {
			os << "invalid line '" << line << "': missing column symbol";
			throw invalid_argument(os.str());
		}

		string &value = result[string(line.cbegin(), column)];
		auto valueStart = find_if_not(column+1, line.cend(), [](const char &c){return isspace(c) != 0;});
		if (valueStart == line.cend()) {
			os << "invalid line '" << line << "': missing value";
			throw invalid_argument(os.str());
		}

		value.assign(valueStart, line.cend());
	} while (!is.eof());
	return result;
}

int HttpAuthModule::onHttpResponseCb(nth_client_magic_t *magic, nth_client_t *request, const http_t *http) {
	const char *defaultErrMsg = "unhandled exception in C callback";
	auto *ctx = reinterpret_cast<pair<HttpAuthModule &, FlexisipAuthStatus &> *>(magic);
	try {
		ctx->first.onHttpResponse(ctx->second, request, http);
	} catch (std::exception &e) {
		SLOGE << defaultErrMsg << ": " << e.what();
	} catch (...) {
		SLOGE << defaultErrMsg;
	}
	delete ctx;
	return 0;
}

std::string HttpAuthModule::toString(const http_payload_t *httpPayload) {
	if (httpPayload == nullptr || httpPayload->pl_data == nullptr || httpPayload->pl_len == 0) {
		return string();
	}
	return string(httpPayload->pl_data, httpPayload->pl_len);
}

bool HttpAuthModule::validSipCode(int sipCode) {
	const auto it = find(sValidSipCodes.cbegin(), sValidSipCodes.cend(), sipCode);
	return (it != sValidSipCodes.cend());
}

std::array<int, 4> HttpAuthModule::sValidSipCodes = {200, 401, 407, 403};
