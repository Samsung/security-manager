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
#

SET(TARGET_PLUGIN_SERVICE "license-manager-plugin-service")
SET(TARGET_PLUGIN_CLIENT "license-manager-plugin-client")
SET(LM_DIR ${PROJECT_SOURCE_DIR}/src/license-manager)

PKG_CHECK_MODULES(LMP_DEP
    REQUIRED
    cynara-plugin)

INCLUDE_DIRECTORIES(
    ${LM_DIR}/common
    ${LM_DIR}/plugin
    SYSTEM
    ${LMP_DEP_INCLUDE_DIRS})

SET(LMP_SERVICE_SOURCES
    ${LM_DIR}/plugin/service.cpp)

SET(LMP_CLIENT_SOURCES
    ${LM_DIR}/plugin/client.cpp)

LINK_DIRECTORIES(${LMP_DEP_LIBRARY_DIRS})

ADD_LIBRARY(${TARGET_PLUGIN_SERVICE} SHARED ${LMP_SERVICE_SOURCES})
ADD_LIBRARY(${TARGET_PLUGIN_CLIENT} SHARED ${LMP_CLIENT_SOURCES})

SET_TARGET_PROPERTIES(${TARGET_PLUGIN_SERVICE}
    PROPERTIES
        COMPILE_FLAGS "-fvisibility=default"
    )

SET_TARGET_PROPERTIES(${TARGET_PLUGIN_CLIENT}
    PROPERTIES
        COMPILE_FLAGS "-fvisibility=default"
    )

TARGET_LINK_LIBRARIES(${TARGET_PLUGIN_SERVICE}
    ${LMP_DEP_LIBRARIES})
TARGET_LINK_LIBRARIES(${TARGET_PLUGIN_CLIENT}
    ${LMP_DEP_LIBRARIES})

INSTALL(TARGETS ${TARGET_PLUGIN_SERVICE}
    DESTINATION ${LIB_INSTALL_DIR}/cynara/plugin/service/)
INSTALL(TARGETS ${TARGET_PLUGIN_CLIENT}
    DESTINATION ${LIB_INSTALL_DIR}/cynara/plugin/client/)

ADD_SUBDIRECTORY(agent)
