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
/*
 * @file       privilege-info.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#include <privilege_info.h> // external privilege-info header

#include "privilege-info.h" // header for this file

#include <dpl/log/log.h>
#include <smack-labels.h>

namespace SecurityManager {

PrivilegeInfo::PrivilegeInfo(uid_t uid, const std::string &label, const std::string &privilege) :
    m_uid(uid),
    m_privilege(privilege)
{
    try {
        SmackLabels::generateAppPkgNameFromLabel(label, m_appId, m_pkgId);
    } catch(const SmackException::InvalidLabel&) {
        LogDebug("Not an application label " << label);
        ThrowMsg(Exception::NotApplication, "Not an application label");
    }
}

bool PrivilegeInfo::hasAttribute(PrivilegeAttr attr)
{
    privilege_manager_privilege_type_e type;
    int ret = privilege_info_get_privilege_type(m_uid, m_pkgId.c_str(), m_privilege.c_str(), &type);
    if (ret != PRVMGR_ERR_NONE)
        ThrowMsg(Exception::UnknownError, "Error while getting privilege type " << ret);

    switch (attr) {
    case PrivilegeAttr::PRIVACY:
        return (type == PRIVILEGE_MANAGER_PRIVILEGE_TYPE_PRIVACY);
    case PrivilegeAttr::BLACKLIST:
        return (type == PRIVILEGE_MANAGER_PRIVILEGE_TYPE_BLACKLIST);
    default:
        ThrowMsg(Exception::InvalidAttribute, "Invalid privilege attribute " << static_cast<int>(attr));
    }
}

bool PrivilegeInfo::isAppWhiteListed(const std::string &pkgName)
{
    return privilege_info_is_privacy_white_list_application(pkgName.c_str());
}

} // namespace SecurityManager

