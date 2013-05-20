PKG_CHECK_MODULES(SECURITY_SERVER_DEP
    dlog
    openssl
    libsmack
    libprivilege-control
    REQUIRED
    )

SET(SECURITY_SERVER_PATH ${PROJECT_SOURCE_DIR}/src)
SET(SERVER2_PATH ${PROJECT_SOURCE_DIR}/src/server2)

SET(SECURITY_SERVER_SOURCES
    ${SECURITY_SERVER_PATH}/communication/security-server-comm.c
    ${SECURITY_SERVER_PATH}/server/security-server-cookie.c
    ${SECURITY_SERVER_PATH}/server/security-server-main.c
    ${SECURITY_SERVER_PATH}/server/security-server-password.c
    ${SECURITY_SERVER_PATH}/util/security-server-util-common.c
    ${SECURITY_SERVER_PATH}/server/security-server-system-observer.c
    ${SECURITY_SERVER_PATH}/server/security-server-rules-revoker.c
    ${SECURITY_SERVER_PATH}/util/smack-check.c
    ${SERVER2_PATH}/main/socket-manager.cpp
    ${SERVER2_PATH}/main/server2-main.cpp
    ${SERVER2_PATH}/service/data-share.cpp
    ${SERVER2_PATH}/service/echo.cpp
    )

SET_SOURCE_FILES_PROPERTIES(
    ${SECURITY_SERVER_SOURCES}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE")
        # with flag -DSECURITY_SERVER_DEBUG_DLOG debug and warning logs on

INCLUDE_DIRECTORIES(
    ${SECURITY_SERVER_PATH}/include
    ${SERVER2_PATH}/main
    ${SERVER2_PATH}/common
    ${SERVER2_PATH}/service
    ${SERVER2_PATH}/dpl/core/include
    ${SERVER2_PATH}/dpl/log/include
    ${SECURITY_SERVER_DEP_INCLUDE_DIRS}
    )

ADD_EXECUTABLE(${TARGET_SECURITY_SERVER} ${SECURITY_SERVER_SOURCES})

TARGET_LINK_LIBRARIES(${TARGET_SECURITY_SERVER}
    ${SECURITY_SERVER_DEP_LIBRARIES}
    ${TARGET_SERVER_COMMON}
    )

################################################################################

SET(SECURITY_CLIENT_VERSION_MAJOR 1)
SET(SECURITY_CLIENT_VERSION ${SECURITY_CLIENT_VERSION_MAJOR}.0.1)

INCLUDE_DIRECTORIES(
    ${SECURITY_SERVER_PATH}/server2/client
    ${SECURITY_SERVER_PATH}/server2/common
    ${SECURITY_SERVER_PATH}/server2/dpl/core/include
    ${SECURITY_SERVER_PATH}/server2/dpl/log/include
    )

SET(SECURITY_CLIENT_SOURCES
    ${SECURITY_SERVER_PATH}/server2/client/client-common.cpp
    ${SECURITY_SERVER_PATH}/server2/client/client-shared-memory.cpp
    ${SECURITY_SERVER_PATH}/client/security-server-client.c
    ${SECURITY_SERVER_PATH}/communication/security-server-comm.c
    ${SECURITY_SERVER_PATH}/util/smack-check.c
    )

ADD_LIBRARY(${TARGET_SECURITY_CLIENT} SHARED ${SECURITY_CLIENT_SOURCES})

# and COMPILE_FLAGS "-DSECURITY_SERVER_DEBUG_DLOG" to turn on debug and warning logs
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

INSTALL(TARGETS ${TARGET_SECURITY_CLIENT} DESTINATION ${LIB_INSTALL_DIR})

INSTALL(TARGETS ${TARGET_SECURITY_SERVER} DESTINATION bin)

INSTALL(FILES
    ${SECURITY_SERVER_PATH}/include/security-server.h
    DESTINATION /usr/include/security-server
    )

################################################################################

#CONFIGURE_FILE(security-server.pc.in security-server.pc @ONLY)
#INSTALL

################################################################################

ADD_SUBDIRECTORY(server2)
