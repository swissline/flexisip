/*
 Flexisip, a flexible SIP proxy server with media capabilities.
 Copyright (C) 2012  Belledonne Communications SARL.

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

#ifndef forkbasiccontext_hh
#define forkbasiccontext_hh

#include "agent.hh"
#include "event.hh"
#include "transaction.hh"
#include "forkcontext.hh"
#include <list>
#include <map>

class ForkBasicContext: public ForkContext {
private:
	int mDeliveredCount;
	std::shared_ptr<ResponseSipEvent> mBestResponse;
	void forward(const std::shared_ptr<ResponseSipEvent> &ev);
	void store(std::shared_ptr<ResponseSipEvent> &event);
	su_timer_t *mDecisionTimer; /*timeout after which an answer must be sent through the incoming transaction even if no success response was received on the outgoing transactions*/
public:
	ForkBasicContext(Agent *agent, const std::shared_ptr<RequestSipEvent> &event, std::shared_ptr<ForkContextConfig> cfg, ForkContextListener* listener);
	virtual ~ForkBasicContext();
	virtual void onNew(const std::shared_ptr<IncomingTransaction> &transaction);
	virtual void onRequest(const std::shared_ptr<IncomingTransaction> &transaction, std::shared_ptr<RequestSipEvent> &event);
	virtual void onDestroy(const std::shared_ptr<IncomingTransaction> &transaction);
	virtual void onNew(const std::shared_ptr<OutgoingTransaction> &transaction);
	virtual void onResponse(const std::shared_ptr<OutgoingTransaction> &transaction, std::shared_ptr<ResponseSipEvent> &event);
	virtual void onDestroy(const std::shared_ptr<OutgoingTransaction> &transaction);
	virtual bool onNewRegister(const sip_contact_t *ctt);
	virtual void checkFinished();
private:
	void finishIncomingTransaction();
	static void sOnDecisionTimer(su_root_magic_t *magic, su_timer_t *t, su_timer_arg_t *arg);
	void onDecisionTimer();
};


#endif /* forkbasiccontext_hh */