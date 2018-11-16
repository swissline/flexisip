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

#include <sstream>
#include <stdexcept>

#include <sofia-sip/auth_plugin.h>
#include <sofia-sip/su_tagarg.h>

#include "log/logmanager.hh"

#include "auth-module.hh"

using namespace std;

struct auth_plugin_t {
	AuthModuleWrapper *backPtr;
};

struct auth_mod_plugin_t {
	auth_mod_t module[1];
	auth_plugin_t plugin[1];
};

AuthModuleWrapper::AuthModuleWrapper(su_root_t *root, tag_type_t tag, tag_value_t value, ...) {
	ta_list ta;

	registerScheme();

	ta_start(ta, tag, value);
	mAm = auth_mod_create(root, AUTHTAG_METHOD(sMethodName), ta_tags(ta));
	ta_end(ta);

	if (mAm == nullptr) {
		ostringstream os;
		os << "couldn't create '" << sMethodName << "' authentication module";
		throw logic_error(os.str());
	}

	(AUTH_PLUGIN(mAm))->backPtr = this;
}

void AuthModuleWrapper::checkCb(auth_mod_t *am, auth_status_t *as, msg_auth_t *auth, auth_challenger_t const *ch) noexcept {
	(AUTH_PLUGIN(am))->backPtr->onCheck(as, auth, ch);
}

void AuthModuleWrapper::challengeCb(auth_mod_t *am, auth_status_t *as, auth_challenger_t const *ach) noexcept {
	(AUTH_PLUGIN(am))->backPtr->onChallenge(as, ach);
}

void AuthModuleWrapper::cancelCb(auth_mod_t *am, auth_status_t *as) noexcept {
	(AUTH_PLUGIN(am))->backPtr->onCancel(as);
}

void AuthModuleWrapper::registerScheme() {
	if (!sSchemeRegistered) {
		if (auth_mod_register_plugin(&sAuthScheme) != 0) {
			ostringstream os;
			os << "couldn't register '" << sMethodName << "' authentication plugin";
			throw logic_error(os.str());
		}
	}
}

const char *AuthModuleWrapper::sMethodName = "flexisip";

auth_scheme_t AuthModuleWrapper::sAuthScheme = {
	sMethodName,
	sizeof(auth_mod_plugin_t),
	auth_init_default,
	checkCb,
	challengeCb,
	cancelCb,
	auth_destroy_default
};

bool AuthModuleWrapper::sSchemeRegistered = false;
