PKG_CHECK_MODULES(SERVER_DEP
    REQUIRED
    libcap
    libsmack
    libprivilege-control
    libsystemd-daemon
    )

INCLUDE_DIRECTORIES(SYSTEM
    ${SERVER_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${SERVER_PATH}/main/include
    ${SERVER_PATH}/service/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

SET(SERVER_SOURCES
    ${SERVER_PATH}/main/security-manager-util.cpp
    ${SERVER_PATH}/main/generic-socket-manager.cpp
    ${SERVER_PATH}/main/socket-manager.cpp
    ${SERVER_PATH}/main/server-main.cpp
    ${SERVER_PATH}/service/smack-common.cpp
    ${SERVER_PATH}/service/smack-rules.cpp
    ${SERVER_PATH}/service/installer.cpp
    )

ADD_EXECUTABLE(${TARGET_SERVER} ${SERVER_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_SERVER}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden")

TARGET_LINK_LIBRARIES(${TARGET_SERVER}
    ${TARGET_COMMON}
    ${SERVER_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_SERVER} DESTINATION bin)
