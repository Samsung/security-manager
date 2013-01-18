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
#
# @file     CMakeLists.txt
# @author   Bartlomiej Grzelewski (b.grzelewski@samsung.com)
#

#SET(DAEMON_BASIC_DEP
#    dpl-efl
#    dpl-dbus-efl
#    dpl-utils-efl
#    libsoup-2.4
#    openssl
#    libsmack
#  )
#
#IF(SMACK_ENABLE)
#    LIST(APPEND DAEMON_BASIC_DEP libprivilege-control)
#ENDIF(SMACK_ENABLE)
#
#PKG_CHECK_MODULES(DAEMON_DEP
#    ${DAEMON_BASIC_DEP}
#    REQUIRED)
#
#SET(DAEMON_SOURCES_PATH ${PROJECT_SOURCE_DIR}/src)
#
#SET(DAEMON_SOURCES
#    #socket connection
#    ${PROJECT_SOURCE_DIR}/socket_connection/connection/SocketConnection.cpp
#    ${PROJECT_SOURCE_DIR}/socket_connection/connection/SocketStream.cpp
#    #caller
#    ${DAEMON_SOURCES_PATH}/services/caller/security_caller.cpp
#    #daemon
#    ${DAEMON_SOURCES_PATH}/daemon/dbus/security_dbus_service.cpp
#    ${DAEMON_SOURCES_PATH}/daemon/sockets/security_socket_service.cpp
#    ${DAEMON_SOURCES_PATH}/daemon/security_daemon.cpp
#    ${DAEMON_SOURCES_PATH}/main.cpp
#    #ocsp
#    ${DAEMON_SOURCES_PATH}/services/ocsp/dbus/ocsp_server_dbus_interface.cpp
#    ${DAEMON_SOURCES_PATH}/services/ocsp/socket/ocsp_service_callbacks.cpp
#    ${DAEMON_SOURCES_PATH}/services/ocsp/ocsp_service.cpp
#    #ace
#    ${DAEMON_SOURCES_PATH}/services/ace/dbus/ace_server_dbus_interface.cpp
#    ${DAEMON_SOURCES_PATH}/services/ace/socket/ace_service_callbacks.cpp
#    ${DAEMON_SOURCES_PATH}/services/ace/ace_service.cpp
#    ${DAEMON_SOURCES_PATH}/services/ace/logic/security_controller.cpp
#    ${DAEMON_SOURCES_PATH}/services/ace/logic/attribute_facade.cpp
#    ${DAEMON_SOURCES_PATH}/services/ace/logic/security_logic.cpp
#    ${DAEMON_SOURCES_PATH}/services/ace/logic/simple_roaming_agent.cpp
#    #popup
#    ${DAEMON_SOURCES_PATH}/services/popup/dbus/popup_response_dbus_interface.cpp
#    ${DAEMON_SOURCES_PATH}/services/popup/socket/popup_service_callbacks.cpp
#  )
#
#SET_SOURCE_FILES_PROPERTIES(${DAEMON_SOURCES} PROPERTIES COMPILE_FLAGS "-std=c++0x")
#
############################## Lets start compilation process ##################
##ace library
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/ace/include)
##socket connection library
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/socket_connection/connection)
##daemon
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/daemon)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/daemon/dbus)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/daemon/sockets/api)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/daemon/sockets)
##caller
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/caller)
##ace
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ace)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ace/dbus)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ace/socket)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ace/socket/api)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ace/logic)
##ocsp
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ocsp)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ocsp/dbus)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ocsp/socket)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ocsp/socket/api)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ocsp/logic)
##popup
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/popup)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/popup/dbus)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/popup/socket)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/popup/socket/api)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/popup/logic)
#INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/ace/include)
#INCLUDE_DIRECTORIES(${DAEMON_DEP_INCLUDE_DIRS})
#
#ADD_EXECUTABLE(${TARGET_DAEMON}
#    ${DAEMON_SOURCES})
#
#TARGET_LINK_LIBRARIES(${TARGET_DAEMON}
#    ${DAEMON_DEP_LIBRARIES}
#    ${TARGET_ACE_LIB}
#    ${TARGET_ACE_DAO_RW_LIB})
#
#INSTALL(TARGETS ${TARGET_DAEMON}
#    DESTINATION bin)
#
#INSTALL(FILES
#    ${PROJECT_SOURCE_DIR}/src/daemon/dbus/org.tizen.SecurityDaemon.service
#    DESTINATION /usr/share/dbus-1/services
#    )
#
#INSTALL(FILES
#    ${PROJECT_SOURCE_DIR}/src/services/ace/ace_server_api.h
#    ${PROJECT_SOURCE_DIR}/src/services/ocsp/ocsp_server_api.h
#    ${PROJECT_SOURCE_DIR}/src/services/popup/popup_response_server_api.h
#    ${PROJECT_SOURCE_DIR}/src/services/popup/popup_ace_data_types.h
#    ${PROJECT_SOURCE_DIR}/src/daemon/dbus/security_daemon_dbus_config.h
#    DESTINATION /usr/include/wrt-security
#    )
#
ADD_SUBDIRECTORY(security-srv)
