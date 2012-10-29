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

SET(DAEMON_BASIC_DEP
    dpl-efl
    dpl-wrt-dao-rw
    dpl-dbus-efl
    dpl-utils-efl
    libsoup-2.4
    dlog
    openssl
    libsmack
  )

IF(SMACK_ENABLE)
    LIST(APPEND DAEMON_BASIC_DEP libprivilege-control)
ENDIF(SMACK_ENABLE)

PKG_CHECK_MODULES(DAEMON_DEP
    ${DAEMON_BASIC_DEP}
    REQUIRED)


SET(DAEMON_SOURCES_PATH ${PROJECT_SOURCE_DIR}/src)

SET(DAEMON_SOURCES
    ${DAEMON_SOURCES_PATH}/daemon/dbus/security_dbus_service.cpp
    ${DAEMON_SOURCES_PATH}/daemon/security_daemon.cpp
    ${DAEMON_SOURCES_PATH}/main.cpp
    #ocsp
    ${DAEMON_SOURCES_PATH}/services/ocsp/dbus/ocsp_server_dbus_interface.cpp
    ${DAEMON_SOURCES_PATH}/services/ocsp/ocsp_service.cpp
    #ace
    ${DAEMON_SOURCES_PATH}/services/ace/dbus/ace_server_dbus_interface.cpp
    ${DAEMON_SOURCES_PATH}/services/ace/ace_service.cpp
    ${DAEMON_SOURCES_PATH}/services/ace/logic/security_controller.cpp
    ${DAEMON_SOURCES_PATH}/services/ace/logic/attribute_facade.cpp
    ${DAEMON_SOURCES_PATH}/services/ace/logic/security_logic.cpp
    ${DAEMON_SOURCES_PATH}/services/ace/logic/simple_roaming_agent.cpp
    #popup
    ${DAEMON_SOURCES_PATH}/services/popup/dbus/popup_response_dbus_interface.cpp
  )

SET_SOURCE_FILES_PROPERTIES(${DAEMON_SOURCES} PROPERTIES COMPILE_FLAGS "-std=c++0x")
SET(DAEMON_SOURCES
    ${DAEMON_SOURCES}
    #security-server
    ${DAEMON_SOURCES_PATH}/security-srv/communication/security-server-comm.c
    ${DAEMON_SOURCES_PATH}/security-srv/server/security-server-cookie.c
    ${DAEMON_SOURCES_PATH}/security-srv/server/security-server-main.c
    ${DAEMON_SOURCES_PATH}/security-srv/server/security-server-password.c
    ${DAEMON_SOURCES_PATH}/security-srv/util/security-server-util-common.c)

SET_SOURCE_FILES_PROPERTIES(
    ${DAEMON_SOURCES_PATH}/security-srv/communication/security-server-comm.c
    PROPERTIES COMPILE_FLAGS "-D_GNU_SOURCE")

############################# Lets start compilation process ##################
#ace library
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/ace/include)
#daemon
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/daemon)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/daemon/dbus)
#ace
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ace/dbus)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ace/logic)
#ocsp
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ocsp/dbus)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/ocsp/logic)
#popup
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/popup/dbus)
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/services/popup/logic)
INCLUDE_DIRECTORIES(${DAEMON_DEP_INCLUDE_DIRS})
#security-server
INCLUDE_DIRECTORIES(${PROJECT_SOURCE_DIR}/src/security-srv/include)

ADD_EXECUTABLE(${TARGET_DAEMON}
    ${DAEMON_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_DAEMON}
    ${DAEMON_DEP_LIBRARIES}    
    ${TARGET_ACE_LIB}
    ${TARGET_ACE_DAO_RW_LIB})



###################################################################################################
## for libsecurity-server-client.so (library)
pkg_check_modules(pkgs REQUIRED dlog openssl libsmack)

SET(VERSION_MAJOR 1)
SET(VERSION ${VERSION_MAJOR}.0.1)

SET(libsecurity-server-client_SOURCES
    ${DAEMON_SOURCES_PATH}/security-srv/client/security-server-client.c
    ${DAEMON_SOURCES_PATH}/security-srv/communication/security-server-comm.c)
SET(libsecurity-server-client_LDFLAGS " -module -avoid-version")
SET(libsecurity-server-client_CFLAGS  " ${CFLAGS} -fPIC -I${sec_svr_include_dir} ${debug_type} -D_GNU_SOURCE ")
#SET(libsecurity-server-client_LIBADD "")

ADD_LIBRARY(security-server-client SHARED ${libsecurity-server-client_SOURCES})
TARGET_LINK_LIBRARIES(security-server-client ${pkgs_LDFLAGS})
SET_TARGET_PROPERTIES(security-server-client PROPERTIES SOVERSION ${VERSION_MAJOR})
SET_TARGET_PROPERTIES(security-server-client PROPERTIES VERSION ${VERSION})
SET_TARGET_PROPERTIES(security-server-client PROPERTIES COMPILE_FLAGS "${libsecurity-server-client_CFLAGS}")
###################################################################################################

INSTALL(TARGETS ${TARGET_DAEMON}
    DESTINATION bin)

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/src/daemon/dbus/org.tizen.SecurityDaemon.service
    DESTINATION /usr/share/dbus-1/services
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/src/services/ace/dbus/api/ace_server_api.h
    ${PROJECT_SOURCE_DIR}/src/services/ocsp/dbus/api/ocsp_server_api.h
    ${PROJECT_SOURCE_DIR}/src/services/popup/dbus/api/popup_response_server_api.h
    ${PROJECT_SOURCE_DIR}/src/services/popup/dbus/api/popup_ace_data_types.h
    ${PROJECT_SOURCE_DIR}/src/daemon/dbus/security_daemon_dbus_config.h
    DESTINATION /usr/include/wrt-security
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/src/security-srv/include/security-server.h
    DESTINATION /usr/include/security-server
    )

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/src/security-srv/mw-list
    DESTINATION /usr/share/security-server/)

INSTALL(FILES
    ${PROJECT_SOURCE_DIR}/src/security-srv/security-serverd
    DESTINATION /etc/rc.d/init.d)

INSTALL(TARGETS security-server-client DESTINATION lib)

