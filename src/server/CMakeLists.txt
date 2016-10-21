PKG_CHECK_MODULES(SERVER_DEP
    REQUIRED
    libsystemd
    cynara-client
    )

FIND_PACKAGE(Threads REQUIRED)

INCLUDE_DIRECTORIES(SYSTEM
    ${SERVER_DEP_INCLUDE_DIRS}
    ${Threads_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${SERVER_PATH}/main/include
    ${SERVER_PATH}/service/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    ${DPL_PATH}/db/include
    )

SET(SERVER_SOURCES
    ${SERVER_PATH}/main/generic-socket-manager.cpp
    ${SERVER_PATH}/main/socket-manager.cpp
    ${SERVER_PATH}/main/server-main.cpp
    ${SERVER_PATH}/service/base-service.cpp
    ${SERVER_PATH}/service/service.cpp
    )

ADD_EXECUTABLE(${TARGET_SERVER} ${SERVER_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_SERVER}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE")

TARGET_LINK_LIBRARIES(${TARGET_SERVER}
    ${TARGET_COMMON}
    ${CMAKE_THREAD_LIBS_INIT}
    ${SERVER_DEP_LIBRARIES}
    "-pthread"
    "-pie"
    )

########## CLEANUP SERVICE ######################################
SET(CLEANUP_SOURCES
    ${SERVER_PATH}/cleanup/security-manager-cleanup.cpp
    )
ADD_EXECUTABLE(${TARGET_CLEANUP} ${CLEANUP_SOURCES})
SET_TARGET_PROPERTIES(${TARGET_CLEANUP}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden -fPIE")

TARGET_LINK_LIBRARIES(${TARGET_CLEANUP}
    ${TARGET_COMMON}
    "-pie"
    )
INSTALL(TARGETS ${TARGET_CLEANUP} DESTINATION ${BIN_INSTALL_DIR})
INSTALL(TARGETS ${TARGET_SERVER} DESTINATION ${BIN_INSTALL_DIR})

