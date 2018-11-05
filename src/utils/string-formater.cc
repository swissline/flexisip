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

#include "string-formater.hh"

using namespace std;

std::string StringFormater::format(const std::map<std::string, std::string> &values) const {
	string result;
	auto lastIt = mTemplate.cbegin();
	do {
		auto it1 = find(lastIt, mTemplate.cend(), '$');
		if (it1 != mTemplate.cend()) {
			result.insert(result.cend(), lastIt, it1-1);
			auto it2 = find_if_not(++it1, mTemplate.cend(), isKeywordChar);
			result += values.at(string(it1, it2));
			lastIt = (it2 != mTemplate.cend() ? it2+1 : it2);
		}
	} while (lastIt != mTemplate.cend());
	return result;
}

bool StringFormater::isKeywordChar(char c) {
	return ((c >= 'A' && c <= 'z') || c == '-');
}
