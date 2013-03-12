# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
# @file        CMakeLists.txt
# @author
# @brief
#

############################# Check minimum CMake version #####################

CMAKE_MINIMUM_REQUIRED(VERSION 2.6)
PROJECT("security-server")

############################# cmake packages ##################################

INCLUDE(FindPkgConfig)

############################# compilation defines #############################

# EMPTY

############################# compiler flags ##################################

SET(CMAKE_C_FLAGS_PROFILING    "-O0 -g -pg")
SET(CMAKE_CXX_FLAGS_PROFILING  "-O0 -std=c++0x -g -pg")
SET(CMAKE_C_FLAGS_DEBUG        "-O0 -g")
SET(CMAKE_CXX_FLAGS_DEBUG      "-O0 -std=c++0x -g")
SET(CMAKE_C_FLAGS_RELEASE      "-O2 -g")
SET(CMAKE_CXX_FLAGS_RELEASE    "-O2 -std=c++0x -g")
SET(CMAKE_C_FLAGS_CCOV         "-O2 -g --coverage")
SET(CMAKE_CXX_FLAGS_CCOV       "-O2 -std=c++0x -g --coverage")

#SET(SMACK_ENABLE ON)

OPTION(DPL_LOG "DPL logs status" ON)
IF(DPL_LOG)
    MESSAGE(STATUS "Logging enabled for DPL")
    ADD_DEFINITIONS("-DDPL_LOGS_ENABLED")
ELSE(DPL_LOG)
    MESSAGE(STATUS "Logging disabled for DPL")
ENDIF(DPL_LOG)

# If supported for the target machine, emit position-independent code,suitable
# for dynamic linking and avoiding any limit on the size of the global offset
# table. This option makes a difference on the m68k, PowerPC and SPARC.
# (BJ: our ARM too?)
ADD_DEFINITIONS("-fPIC")

# Set the default ELF image symbol visibility to hidden - all symbols will be
# marked with this unless overridden within the code.
#ADD_DEFINITIONS("-fvisibility=hidden")

# Set compiler warning flags
#ADD_DEFINITIONS("-Werror")                      # Make all warnings into errors.
ADD_DEFINITIONS("-Wall")                        # Generate all warnings
ADD_DEFINITIONS("-Wextra")                      # Generate even more extra warnings
ADD_DEFINITIONS("-Wno-variadic-macros")         # Inhibit variadic macros warnings (needed for ORM)
ADD_DEFINITIONS("-Wno-deprecated")               # No warnings about deprecated features
ADD_DEFINITIONS("-std=c++0x")               # No warnings about deprecated features

ADD_DEFINITIONS("-DSOCKET_CONNECTION")      #defines sockets as used IPC
#ADD_DEFINITIONS("-DDBUS_CONNECTION")        #defines DBus as used IPC

STRING(REGEX MATCH "([^.]*)" API_VERSION "${VERSION}")
ADD_DEFINITIONS("-DAPI_VERSION=\"$(API_VERSION)\"")

IF(SMACK_ENABLE)
    ADD_DEFINITIONS("-DWRT_SMACK_ENABLED")
ENDIF(SMACK_ENABLE)

############################# Targets names ###################################

SET(TARGET_DAEMON "security-server")
SET(TARGET_ACE_DAO_RO_LIB "ace-dao-ro")
SET(TARGET_ACE_DAO_RW_LIB "ace-dao-rw")
SET(TARGET_ACE_LIB "ace")
SET(TARGET_ACE_CLIENT_LIB "ace-client")
SET(TARGET_ACE_SETTINGS_LIB "ace-settings")
SET(TARGET_ACE_INSTALL_LIB "ace-install")
SET(TARGET_ACE_POPUP_VALIDATION_LIB "ace-popup-validation")
SET(TARGET_COMMUNICATION_CLIENT_LIB "communication-client")
SET(TARGET_WRT_OCSP_LIB "wrt-ocsp")
SET(TARGET_SEC_SRV_LIB "sec-srv")
SET(security-server-client "security-server-client")

############################# Communicatin Client #############################

SET(COMMUNICATION_CLIENT_DIR
    ${PROJECT_SOURCE_DIR}/communication_client
    )

SET(COMMUNICATION_CLIENT_SRC_DIR
    ${COMMUNICATION_CLIENT_DIR}/src
    )

SET(COMMUNICATION_CLIENT_INCLUDE_DIR
    ${COMMUNICATION_CLIENT_DIR}/include
    )

SET(COMMUNICATION_CLIENT_SOURCES
    ${COMMUNICATION_CLIENT_SRC_DIR}/SecurityCommunicationClient.cpp
    ${PROJECT_SOURCE_DIR}/socket_connection/client/SecuritySocketClient.cpp
    ${PROJECT_SOURCE_DIR}/socket_connection/connection/SocketConnection.cpp
    ${PROJECT_SOURCE_DIR}/socket_connection/connection/SocketStream.cpp
    )

SET(COMMUNICATION_CLIENT_INCLUDES
    ${COMMUNICATION_CLIENT_DEPS_INCLUDE_DIRS}
    ${COMMUNICATION_CLIENT_INCLUDE_DIR}
    ${PROJECT_SOURCE_DIR}/src/daemon/sockets
    ${PROJECT_SOURCE_DIR}/src/daemon/dbus
    ${PROJECT_SOURCE_DIR}/src/daemon/socket
    ${PROJECT_SOURCE_DIR}/src/daemon/socket/api
    ${PROJECT_SOURCE_DIR}/socket_connection/client
    ${PROJECT_SOURCE_DIR}/socket_connection/connection
    )

############################# subdirectories ##################################

ADD_SUBDIRECTORY(ace)
ADD_SUBDIRECTORY(ace_client)
ADD_SUBDIRECTORY(ace_common)
ADD_SUBDIRECTORY(ace_install)
ADD_SUBDIRECTORY(ace_settings)
ADD_SUBDIRECTORY(ace_popup_validation)
ADD_SUBDIRECTORY(communication_client)
ADD_SUBDIRECTORY(wrt_ocsp)
ADD_SUBDIRECTORY(src)
ADD_SUBDIRECTORY(build)
ADD_SUBDIRECTORY(etc)

