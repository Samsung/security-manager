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
# @file        CMakeLists.txt
# @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
# @author      Tomasz Swierczek (t.swierczek@samsung.com)
# @brief
#

CONFIGURE_FILE(security-dao-ro.pc.in security-dao-ro.pc @ONLY)
CONFIGURE_FILE(security-dao-rw.pc.in security-dao-rw.pc @ONLY)
CONFIGURE_FILE(security.pc.in security.pc @ONLY)
INSTALL(FILES
    ${CMAKE_BINARY_DIR}/build/ace/security-dao-ro.pc
    ${CMAKE_BINARY_DIR}/build/ace/security-dao-rw.pc
    ${CMAKE_BINARY_DIR}/build/ace/security.pc
    DESTINATION
    lib/pkgconfig
    )
  
