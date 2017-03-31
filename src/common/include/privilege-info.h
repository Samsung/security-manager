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
 * @file       privilege-info.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    1.0
 */

#pragma once

#include <string>
#include <functional>

#include <dpl/exception.h>

namespace SecurityManager {

class PrivilegeInfo {
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, NotApplication)
        DECLARE_EXCEPTION_TYPE(Base, InvalidAttribute)
        DECLARE_EXCEPTION_TYPE(Base, UnknownError)
    };

    enum class PrivilegeAttr {
        PRIVACY = 1,
        BLACKLIST
    };

    PrivilegeInfo(uid_t uid, const std::string &label, const std::string &privilege);

    bool hasAttribute(PrivilegeAttr attr);

    static bool isAppWhiteListed(const std::string &pkgName);

private:
    uid_t m_uid;
    std::string m_appId;
    std::string m_pkgId;
    std::string m_privilege;
};

} // namespace SecurityManager


