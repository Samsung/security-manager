/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file        protocols.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       List of all protocols supported by security manager.
 */

#include <protocols.h>
#include <cstddef>


namespace SecurityManager {

#define SOCKET_PATH_PREFIX "/run/"
#define SOCKET_PATH_PREFIX_SECURITY_MANAGER SOCKET_PATH_PREFIX "security-manager/"

char const * const SERVICE_SOCKET_INSTALLER =
        SOCKET_PATH_PREFIX_SECURITY_MANAGER "security-manager-installer.socket";

} // namespace SecurityManager

