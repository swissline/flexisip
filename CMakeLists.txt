############################################################################
# CMakeLists.txt
# Copyright (C) 2014  Belledonne Communications, Grenoble France
# 
############################################################################
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
# 
############################################################################
cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)

project(flexisip C CXX)

set(FLEXISIP_MAJOR_VERSION "3")
set(FLEXISIP_MINOR_VERSION "8")
set(FLEXISIP_MICRO_VERSION "0")
set(FLEXISIP_VERSION "${FLEXISIP_MAJOR_VERSION}.${FLEXISIP_MINOR_VERSION}.${FLEXISIP_MICRO_VERSION}")
set(FLEXISIP_SO_VERSION "6")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -DHAVE_CONFIG_H")

list( APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/ ${CMAKE_PREFIX_PATH}/share/cmake/Modules)

find_package(SofiaSipUa)
find_package(ortp)
#find_package(sofia-sip-ua)


include_directories(
	src/
	${CMAKE_CURRENT_BINARY_DIR}
	${CMAKE_CURRENT_BINARY_DIR}/src/
	${SOFIA_SIP_UA_INCLUDE_DIRS}
	${ORTP_INCLUDE_DIRS}
)

link_libraries(${SOFIA_SIP_UA_LIBRARY} ${ORTP_LIB})


configure_file(${PROJECT_SOURCE_DIR}/cmake/flexisip-config.h.in ${PROJECT_BINARY_DIR}/flexisip-config.h)

add_subdirectory(src)