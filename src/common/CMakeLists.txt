SET(COMMON_VERSION_MAJOR 1)
SET(COMMON_VERSION ${COMMON_VERSION_MAJOR}.0.2)

PKG_CHECK_MODULES(COMMON_DEP
    REQUIRED
    libsystemd
    libsmack
    db-util
    cynara-admin
    cynara-client-async
    libtzplatform-config
    security-privilege-manager
    )

IF(DPL_WITH_DLOG)
    PKG_CHECK_MODULES(DLOG_DEP REQUIRED dlog)
ENDIF(DPL_WITH_DLOG)

FIND_PACKAGE(Boost REQUIRED)

INCLUDE_DIRECTORIES(SYSTEM
    ${COMMON_DEP_INCLUDE_DIRS}
    ${DLOG_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${INCLUDE_PATH}
    ${COMMON_PATH}/include
    ${LM_COMMON_PATH}
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    ${DPL_PATH}/db/include
    ${Boost_INCLUDE_DIRS}
    )

SET(COMMON_SOURCES
    ${DPL_PATH}/log/src/abstract_log_provider.cpp
    ${DPL_PATH}/log/src/log.cpp
    ${DPL_PATH}/log/src/old_style_log_provider.cpp
    ${DPL_PATH}/core/src/assert.cpp
    ${DPL_PATH}/core/src/binary_queue.cpp
    ${DPL_PATH}/core/src/colors.cpp
    ${DPL_PATH}/core/src/exception.cpp
    ${DPL_PATH}/core/src/noncopyable.cpp
    ${DPL_PATH}/core/src/serialization.cpp
    ${DPL_PATH}/core/src/singleton.cpp
    ${DPL_PATH}/core/src/errno_string.cpp
    ${DPL_PATH}/db/src/naive_synchronization_object.cpp
    ${DPL_PATH}/db/src/sql_connection.cpp
    ${COMMON_PATH}/config.cpp
    ${COMMON_PATH}/connection.cpp
    ${COMMON_PATH}/credentials.cpp
    ${COMMON_PATH}/cynara.cpp
    ${COMMON_PATH}/filesystem.cpp
    ${COMMON_PATH}/file-lock.cpp
    ${COMMON_PATH}/permissible-set.cpp
    ${COMMON_PATH}/protocols.cpp
    ${COMMON_PATH}/message-buffer.cpp
    ${COMMON_PATH}/privilege_db.cpp
    ${COMMON_PATH}/smack-labels.cpp
    ${COMMON_PATH}/smack-rules.cpp
    ${COMMON_PATH}/smack-check.cpp
    ${COMMON_PATH}/service_impl.cpp
    ${COMMON_PATH}/tzplatform-config.cpp
    ${COMMON_PATH}/privilege-info.cpp
    )

IF(DPL_WITH_DLOG)
    SET(COMMON_SOURCES
        ${COMMON_SOURCES}
        ${DPL_PATH}/log/src/dlog_log_provider.cpp)
ENDIF(DPL_WITH_DLOG)

IF(DPL_WITH_SYSTEMD_JOURNAL)
    SET(COMMON_SOURCES
        ${COMMON_SOURCES}
        ${DPL_PATH}/log/src/sd_journal_provider.cpp)
ENDIF(DPL_WITH_SYSTEMD_JOURNAL)

LINK_DIRECTORIES(${COMMON_DEP_LIBRARY_DIRS} ${DLOG_DEP_LIBRARY_DIRS})

ADD_LIBRARY(${TARGET_COMMON} SHARED ${COMMON_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_COMMON}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
        SOVERSION ${COMMON_VERSION_MAJOR}
        VERSION ${COMMON_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_COMMON}
    ${COMMON_DEP_LIBRARIES}
    ${DLOG_DEP_LIBRARIES}
    -lcrypt
    rt
    )

INSTALL(TARGETS ${TARGET_COMMON} DESTINATION ${LIB_INSTALL_DIR})
INSTALL(DIRECTORY DESTINATION ${LOCAL_STATE_DIR}/security-manager/rules)
INSTALL(DIRECTORY DESTINATION ${LOCAL_STATE_DIR}/security-manager/rules-merged)

