# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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

PKG_CHECK_MODULES(WRT_POPUP_DEPS
    dpl-efl
    dpl-event-efl
    dpl-popup-efl        
    REQUIRED
)

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${WRT_POPUP_DEPS_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/src/services/popup/dbus/api
    ${PROJECT_SOURCE_DIR}/ace/include
)

SET(WRT_POPUP_SRCS
    wrt-popup.cpp
    PopupSerializer.cpp
    YesNoPopup.cpp
    CommunicationBox.cpp
)

ADD_EXECUTABLE(${TARGET_WRT_POPUP}
    ${WRT_POPUP_SRCS}
)

TARGET_LINK_LIBRARIES(${TARGET_WRT_POPUP}
    ${WRT_POPUP_DEPS_LIBRARIES}
    ${TARGET_ACE_DAO_RO_LIB}
)

SET_TARGET_PROPERTIES(${TARGET_WRT_POPUP} PROPERTIES
    LINK_FLAGS "-Wl,--as-needed -Wl,--hash-style=both -Wl"
    BUILD_WITH_INSTALL_RPATH ON
    INSTALL_RPATH_USE_LINK_PATH ON
)

INSTALL(TARGETS ${TARGET_WRT_POPUP} DESTINATION bin)
