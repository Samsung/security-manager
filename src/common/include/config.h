/*
 *  Copyright (c) 2015-2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        config.h
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Definition of Configuration options
 */

#pragma once

#include <string>

namespace SecurityManager {

namespace Config {
/* Service name */

extern const std::string SERVICE_NAME;

/* Privileges required from users of our API */
extern const std::string PRIVILEGE_APPINST_USER;
extern const std::string PRIVILEGE_APPINST_ADMIN;
extern const std::string PRIVILEGE_USER_ADMIN;
extern const std::string PRIVILEGE_POLICY_USER;
extern const std::string PRIVILEGE_POLICY_ADMIN;
extern const std::string PRIVILEGE_APPSHARING_ADMIN;
extern const std::string PRIVILEGE_SHM;

/* Files used in permitted label managment */
extern const std::string APPS_LABELS_FILE;

extern const std::string SKEL_DIR;

/* Ask-user policy description */
extern const std::string PRIVACY_POLICY_DESC;

/* true if privacy-related privileges should result in UI-popup question*/
extern const bool IS_ASKUSER_ENABLED;
};

} /* namespace SecurityManager */
