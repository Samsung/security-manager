PKG_CHECK_MODULES(SECURITY_SERVER_DEP
    dlog
    openssl
    libsmack
    libprivilege-control
    libsystemd-daemon
    REQUIRED
    )

SET(SECURITY_SERVER_PATH ${PROJECT_SOURCE_DIR}/src)
SET(SERVER2_PATH ${PROJECT_SOURCE_DIR}/src/server)

SET(SECURITY_SERVER_SOURCES
    ${SERVER2_PATH}/main/security-server-util.cpp
    ${SERVER2_PATH}/main/generic-socket-manager.cpp
    ${SERVER2_PATH}/main/socket-manager.cpp
    ${SERVER2_PATH}/main/server2-main.cpp
    ${SERVER2_PATH}/service/data-share.cpp
    ${SERVER2_PATH}/service/get-gid.cpp
    ${SERVER2_PATH}/service/cookie.cpp
    ${SERVER2_PATH}/service/cookie-jar.cpp
    ${SERVER2_PATH}/service/cookie-common.cpp
    ${SERVER2_PATH}/service/privilege-by-pid.cpp
    ${SERVER2_PATH}/service/password.cpp
    ${SERVER2_PATH}/service/password-file.cpp
    ${SERVER2_PATH}/service/password-manager.cpp
    ${SERVER2_PATH}/service/password-file-buffer.cpp
    ${SERVER2_PATH}/service/smack-common.cpp
    ${SERVER2_PATH}/service/installer.cpp
    )

SET_SOURCE_FILES_PROPERTIES(
    ${SECURITY_SERVER_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden")

INCLUDE_DIRECTORIES(SYSTEM
    ${SECURITY_SERVER_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${SECURITY_SERVER_PATH}/include
    ${SERVER2_PATH}/main
    ${SERVER2_PATH}/common
    ${SERVER2_PATH}/service
    ${SERVER2_PATH}/dpl/core/include
    ${SERVER2_PATH}/dpl/log/include
    )

ADD_EXECUTABLE(${TARGET_SECURITY_SERVER} ${SECURITY_SERVER_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_SECURITY_SERVER}
    ${SECURITY_SERVER_DEP_LIBRARIES}
    ${TARGET_SERVER_COMMON}
    -lcap
    )

################################################################################

SET(SECURITY_CLIENT_VERSION_MAJOR 1)
SET(SECURITY_CLIENT_VERSION ${SECURITY_CLIENT_VERSION_MAJOR}.0.1)

INCLUDE_DIRECTORIES(
    ${SERVER2_PATH}/client
    ${SERVER2_PATH}/common
    ${SERVER2_PATH}/dpl/core/include
    ${SERVER2_PATH}/dpl/log/include
    )

SET(SECURITY_CLIENT_SOURCES
    ${SERVER2_PATH}/client/client-common.cpp
    ${SERVER2_PATH}/client/client-shared-memory.cpp
    ${SERVER2_PATH}/client/client-get-gid.cpp
    ${SERVER2_PATH}/client/client-cookie.cpp
    ${SERVER2_PATH}/client/client-privilege-by-pid.cpp
    ${SERVER2_PATH}/client/client-socket-privilege.cpp
    ${SERVER2_PATH}/client/client-password.cpp
    )

ADD_LIBRARY(${TARGET_SECURITY_CLIENT} SHARED ${SECURITY_CLIENT_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_SECURITY_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${SECURITY_CLIENT_VERSION_MAJOR}
        VERSION ${SECURITY_CLIENT_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_SECURITY_CLIENT}
    ${SECURITY_SERVER_DEP_LIBRARIES}
    ${TARGET_SERVER_COMMON}
    )

################################################################################

SET(SECURITY_MANAGER_CLIENT_VERSION_MAJOR 1)
SET(SECURITY_MANAGER_CLIENT_VERSION ${SECURITY_MANAGER_CLIENT_VERSION_MAJOR}.0.1)

INCLUDE_DIRECTORIES(
    ${SERVER2_PATH}/client
    ${SERVER2_PATH}/common
    ${SERVER2_PATH}/dpl/core/include
    ${SERVER2_PATH}/dpl/log/include
    )

SET(SECURITY_MANAGER_CLIENT_SOURCES
    ${SERVER2_PATH}/client/client-security-manager.cpp
    ${SERVER2_PATH}/client/client-common.cpp
    )

ADD_LIBRARY(${TARGET_SECURITY_MANAGER_CLIENT} SHARED ${SECURITY_MANAGER_CLIENT_SOURCES})

SET_TARGET_PROPERTIES(
    ${TARGET_SECURITY_MANAGER_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=hidden"
        SOVERSION ${SECURITY_MANAGER_CLIENT_VERSION_MAJOR}
        VERSION ${SECURITY_MANAGER_CLIENT_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_SECURITY_MANAGER_CLIENT}
    ${SECURITY_SERVER_DEP_LIBRARIES}
    ${TARGET_SERVER_COMMON}
    )

################################################################################

INSTALL(TARGETS ${TARGET_SECURITY_CLIENT} DESTINATION ${LIB_INSTALL_DIR})
INSTALL(TARGETS ${TARGET_SECURITY_MANAGER_CLIENT} DESTINATION ${LIB_INSTALL_DIR})

INSTALL(TARGETS ${TARGET_SECURITY_SERVER} DESTINATION bin)

INSTALL(FILES
    ${SECURITY_SERVER_PATH}/include/security-server.h
    DESTINATION  ${INCLUDE_INSTALL_DIR}/security-server
    )

INSTALL(FILES
    ${SECURITY_SERVER_PATH}/include/security-manager.h
    DESTINATION  ${INCLUDE_INSTALL_DIR}/security-manager
    )

################################################################################

#CONFIGURE_FILE(security-server.pc.in security-server.pc @ONLY)
#INSTALL

################################################################################

ADD_SUBDIRECTORY(server)
