cmake_minimum_required(VERSION 2.6)
project(ace-thin-client-example)

include(FindPkgConfig)

pkg_check_modules(DEPS
                  dpl-efl
                  REQUIRED)

pkg_search_module(wrt-ace-client REQUIRED wrt-ace-client)

set(TARGET_NAME "ace-thin-client-example")

set(SRCS
    ace-thin-client-example.cpp)

include_directories(${DEPS_INCLUDE_DIRS})
include_directories(${wrt-ace-client_INCLUDE_DIRS})

add_definitions("-DDPL_LOGS_ENABLED")

add_executable(${TARGET_NAME} ${SRCS})

target_link_libraries(${TARGET_NAME}
    ${DEPS_LDFLAGS}
    ${wrt-ace-client_LDFLAGS})
