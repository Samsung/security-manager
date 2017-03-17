/*
 *  Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
/**
 * @file        src/license-manager/agent/agent_logic.cpp
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       This is the place where verification should take place
 */
#include <sstream>
#include <string>

#include <alog.h>

#include <agent_logic.h>
#include <app-runtime.h>

namespace LicenseManager {

std::string AgentLogic::process(const std::string &data) {
    std::stringstream ss(data);
    std::string smack, privilege;
    int uid;
    ss >> smack >> uid >> privilege;
    char *pkgId = nullptr, *appId = nullptr;

    security_manager_identify_privilege_provider(
            privilege.c_str(),
            uid,
            &pkgId,
            &appId);

    ALOGD("App: %s Uid: %d Priv: %s", smack.c_str(), uid, privilege.c_str());
    ALOGD("Privilege: %s is Provided by: %s/%s", privilege.c_str(), appId, pkgId);
    free(pkgId);
    free(appId);

    std::stringstream out;
    out << 1;
    return out.str();
}

} // namespace LicenseManager

