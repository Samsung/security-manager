PKG_CHECK_MODULES(SERVER_DEP
    REQUIRED
    libsystemd-daemon
    libtzplatform-config
    cynara-client
    )

FIND_PACKAGE(Boost REQUIRED COMPONENTS program_options)
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
    )

SET(SERVER_SOURCES
    ${SERVER_PATH}/main/generic-socket-manager.cpp
    ${SERVER_PATH}/main/socket-manager.cpp
    ${SERVER_PATH}/main/server-main.cpp
    ${SERVER_PATH}/service/base-service.cpp
    ${SERVER_PATH}/service/service.cpp
    ${SERVER_PATH}/service/master-service.cpp
    )

ADD_EXECUTABLE(${TARGET_SERVER} ${SERVER_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_SERVER}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fvisibility=hidden")

TARGET_LINK_LIBRARIES(${TARGET_SERVER}
    ${TARGET_COMMON}
    ${CMAKE_THREAD_LIBS_INIT}
    ${SERVER_DEP_LIBRARIES}
    ${Boost_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_SERVER} DESTINATION ${BIN_INSTALL_DIR})
