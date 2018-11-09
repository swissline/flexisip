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

#pragma once

#include <sofia-sip/nth.h>

#include <array>

#include "agent.hh"
#include "module.hh"
#include "utils/string-formater.hh"

class ModuleCustomAuthentication : public Module {
public:
	ModuleCustomAuthentication(Agent *agent) : Module(agent) {}

private:
	void onDeclare(GenericStruct *mc) override;
	void onLoad(const GenericStruct *root) override;
	void onUnload() override;
	void onRequest(std::shared_ptr<RequestSipEvent> &ev) override;
	void onResponse(std::shared_ptr<ResponseSipEvent> &ev) override {}

	void onHttpResponse(nth_client_t *request, const http_t *http);

	void addPendingEvent(nth_client_t *request, const std::shared_ptr<RequestSipEvent> &ev);
	std::shared_ptr<RequestSipEvent> removePendingEvent(nth_client_t *request);

	std::map<std::string, std::string> extractParameters(const MsgSip &msg) const;
	std::map<std::string, std::string> splitCommaSeparatedKeyValuesList(const std::string &kvList) const;
	std::map<std::string, std::string> parseHttpBody(const std::string &body) const;

	static int onHttpResponseCb(nth_client_magic_t *magic, nth_client_t *request, const http_t *http);
	static std::string toString(const http_payload_t *httpPayload);
	static bool validSipCode(int sipCode);

	nth_engine_t *mEngine = nullptr;
	StringFormater mUriFormater;
	std::map<nth_client_t *, std::shared_ptr<RequestSipEvent>> mPendingEvent;

	static std::array<int, 4> mValidSipCodes;
	static ModuleInfo<ModuleCustomAuthentication> mModuleInfo;
};
