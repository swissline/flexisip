/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2018 Belledonne Communications SARL.
 
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

#include "participant-registration-subscription-handler.hh"

using namespace flexisip;
using namespace std;

ParticipantRegistrationSubscriptionHandler::ParticipantRegistrationSubscriptionHandler(const ConferenceServer & server) : mServer(server){
}

string ParticipantRegistrationSubscriptionHandler::getKey (const shared_ptr<const linphone::Address> &address) {
	ostringstream ostr;
	ostr << address->getUsername() << "@" << address->getDomain();
	return ostr.str();
}

void ParticipantRegistrationSubscriptionHandler::subscribe (
	const shared_ptr<linphone::ChatRoom> &chatRoom,
	const shared_ptr<const linphone::Address> &address
) {
	bool toSubscribe = true;
	string key = getKey(address);
	auto range = mSubscriptions.equal_range(key);
	for (auto it = range.first; it != range.second; it++) {
		if (it->second->getChatRoom() == chatRoom) {
			toSubscribe = false;
			break;
		}
	}
	if (toSubscribe) {
		shared_ptr<OwnRegistrationSubscription> subscription(new OwnRegistrationSubscription(mServer, chatRoom, address));
		mSubscriptions.insert(make_pair(key, subscription));
		subscription->start();
	}
}

void ParticipantRegistrationSubscriptionHandler::unsubscribe (
	const shared_ptr<linphone::ChatRoom> &chatRoom,
	const shared_ptr<const linphone::Address> &address
) {
	string key = getKey(address);
	auto range = mSubscriptions.equal_range(key);
	for (auto it = range.first; it != range.second;) {
		if (it->second->getChatRoom() == chatRoom) {
			it->second->stop();
			it = mSubscriptions.erase(it);
		} else {
			it++;
		}
	}
}
