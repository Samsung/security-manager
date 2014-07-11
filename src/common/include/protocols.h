/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
 * @file        protocols.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file contains list of all protocols suported by security-manager.
 */

#ifndef _SECURITY_MANAGER_PROTOCOLS_
#define _SECURITY_MANAGER_PROTOCOLS_

#include <vector>
#include <string>

struct app_inst_req {
    std::string appId;
    std::string pkgId;
    std::vector<std::string> privileges;
    std::vector<std::pair<std::string, int>> appPaths;
};

namespace SecurityManager {

extern char const * const SERVICE_SOCKET_INSTALLER;

enum class SecurityModuleCall
{
    APP_INSTALL,
    APP_UNINSTALL,
    APP_GET_PKGID
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_PROTOCOLS_
