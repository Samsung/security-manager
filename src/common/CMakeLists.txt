SET(COMMON_VERSION_MAJOR 0)
SET(COMMON_VERSION ${COMMON_VERSION_MAJOR}.1.0)

PKG_CHECK_MODULES(COMMON_DEP
    REQUIRED
    libsystemd-journal
#    dlog
    )

INCLUDE_DIRECTORIES(SYSTEM
    ${COMMON_DEP_INCLUDE_DIRS}
    )

INCLUDE_DIRECTORIES(
    ${COMMON_PATH}/include
    ${DPL_PATH}/core/include
    ${DPL_PATH}/log/include
    )

SET(COMMON_SOURCES
    ${COMMON_PATH}/protocols.cpp
    ${COMMON_PATH}/message-buffer.cpp
    ${COMMON_PATH}/smack-common.cpp
    ${DPL_PATH}/log/src/abstract_log_provider.cpp
#    ${DPL_PATH}/log/src/dlog_log_provider.cpp
    ${DPL_PATH}/log/src/sd_journal_provider.cpp
    ${DPL_PATH}/log/src/log.cpp
    ${DPL_PATH}/log/src/old_style_log_provider.cpp
    ${DPL_PATH}/core/src/assert.cpp
    ${DPL_PATH}/core/src/binary_queue.cpp
    ${DPL_PATH}/core/src/colors.cpp
    ${DPL_PATH}/core/src/exception.cpp
    ${DPL_PATH}/core/src/noncopyable.cpp
    ${DPL_PATH}/core/src/serialization.cpp
    ${DPL_PATH}/core/src/singleton.cpp
    )

ADD_LIBRARY(${TARGET_COMMON} SHARED ${COMMON_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_COMMON}
    PROPERTIES
        COMPILE_FLAGS "-D_GNU_SOURCE -fPIC -fvisibility=default"
        SOVERSION ${COMMON_VERSION_MAJOR}
        VERSION ${COMMON_VERSION}
    )

TARGET_LINK_LIBRARIES(${TARGET_COMMON}
    ${COMMON_DEP_LIBRARIES}
    )

INSTALL(TARGETS ${TARGET_COMMON} DESTINATION ${LIB_INSTALL_DIR})
