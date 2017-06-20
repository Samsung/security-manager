# Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
# @file        CMakeLists.txt
# @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
# @brief
#

SET(TARGET_LM_AGENT "license-manager-agent")

PKG_CHECK_MODULES(AGENT_DEP
    REQUIRED
    cynara-agent
    libsystemd
    openssl
    )

SET(AGENT_SOURCES
    ${LM_DIR}/agent/agent.cpp
    ${LM_DIR}/agent/agent_logic.cpp
    ${LM_DIR}/agent/alog.cpp
    ${LM_DIR}/agent/main.cpp
    )

INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/src/include
    ${LM_DIR}/common
    ${LM_DIR}/agent
    SYSTEM
    ${AGENT_DEP_INCLUDE_DIRS}
    )

LINK_DIRECTORIES(${AGENT_DEP_LIBRARY_DIRS})

ADD_EXECUTABLE(${TARGET_LM_AGENT} ${AGENT_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_LM_AGENT}
    PROPERTIES
        COMPILE_FLAGS "-fvisibility=hidden -fPIE")

TARGET_LINK_LIBRARIES(${TARGET_LM_AGENT}
    ${AGENT_DEP_LIBRARIES}
    ${TARGET_CLIENT}
    "-pie"
    )

INSTALL(TARGETS ${TARGET_LM_AGENT} DESTINATION ${BIN_INSTALL_DIR})

