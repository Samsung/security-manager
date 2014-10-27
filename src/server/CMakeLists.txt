PKG_CHECK_MODULES(SERVER_DEP
    REQUIRED
    libsystemd-daemon
    cynara-client
    )

FIND_PACKAGE(Boost REQUIRED)
FIND_PACKAGE(Threads REQUIRED)

INCLUDE_DIRECTORIES(SYSTEM
    ${SERVER_DEP_INCLUDE_DIRS}
    ${Boost_INCLUDE_DIRS}
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
    ${SERVER_PATH}/service/service.cpp
    )

ADD_EXECUTABLE(${TARGET_SERVER} ${SERVER_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_SERVER}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden")

TARGET_LINK_LIBRARIES(${TARGET_SERVER}
    ${TARGET_COMMON}
    ${CMAKE_THREAD_LIBS_INIT}
    ${SERVER_DEP_LIBRARIES}
    )

ADD_CUSTOM_COMMAND(
    OUTPUT ${TARGET_DB} ${TARGET_DB}-journal
    COMMAND sqlite3 ${TARGET_DB} <db/db.sql
    )

# Add a dummy build target to trigger building of ${TARGET_DB}
ADD_CUSTOM_TARGET(DB ALL DEPENDS ${TARGET_DB})

INSTALL(TARGETS ${TARGET_SERVER} DESTINATION ${BIN_INSTALL_DIR})
INSTALL(FILES ${TARGET_DB} DESTINATION ${DB_INSTALL_DIR})
INSTALL(FILES ${TARGET_DB}-journal DESTINATION ${DB_INSTALL_DIR})
