/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cynara.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Wrapper class for Cynara interface
 */

#include <cstring>
#include <string>
#include <vector>
#include "cynara.h"

#include <dpl/log/log.h>

namespace SecurityManager {


CynaraAdminPolicy::CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, Operation operation,
        const std::string &bucket)
{
    this->client = strdup(client.c_str());
    this->user = strdup(user.c_str());
    this->privilege = strdup(privilege.c_str());
    this->bucket = strdup(bucket.c_str());

    if (this->bucket == nullptr || this->client == nullptr ||
        this->user == nullptr || this->privilege == nullptr) {
        free(this->bucket);
        free(this->client);
        free(this->user);
        free(this->privilege);
        ThrowMsg(CynaraException::OutOfMemory,
                std::string("Error in CynaraAdminPolicy allocation."));
    }

    this->result = static_cast<int>(operation);
    this->result_extra = nullptr;
}

CynaraAdminPolicy::CynaraAdminPolicy(const std::string &client, const std::string &user,
    const std::string &privilege, const std::string &goToBucket,
    const std::string &bucket)
{
    this->bucket = strdup(bucket.c_str());
    this->client = strdup(client.c_str());
    this->user = strdup(user.c_str());
    this->privilege = strdup(privilege.c_str());
    this->result_extra = strdup(goToBucket.c_str());
    this->result = CYNARA_ADMIN_BUCKET;

    if (this->bucket == nullptr || this->client == nullptr ||
        this->user == nullptr || this->privilege == nullptr ||
        this->result_extra == nullptr) {
        free(this->bucket);
        free(this->client);
        free(this->user);
        free(this->privilege);
        free(this->result_extra);
        ThrowMsg(CynaraException::OutOfMemory,
                std::string("Error in CynaraAdminPolicy allocation."));
    }
}

CynaraAdminPolicy::CynaraAdminPolicy(CynaraAdminPolicy &&that)
{
    bucket = that.bucket;
    client = that.client;
    user = that.user;
    privilege = that.privilege;
    result_extra = that.result_extra;
    result = that.result;

    that.bucket = nullptr;
    that.client = nullptr;
    that.user = nullptr;
    that.privilege = nullptr;
    that.result_extra = nullptr;
}

CynaraAdminPolicy::~CynaraAdminPolicy()
{
    free(this->bucket);
    free(this->client);
    free(this->user);
    free(this->privilege);
    free(this->result_extra);
}

static bool checkCynaraError(int result, const std::string &msg)
{
    switch (result) {
        case CYNARA_API_SUCCESS:
        case CYNARA_API_ACCESS_ALLOWED:
            return true;
        case CYNARA_API_ACCESS_DENIED:
            return false;
        case CYNARA_API_OUT_OF_MEMORY:
            ThrowMsg(CynaraException::OutOfMemory, msg);
        case CYNARA_API_INVALID_PARAM:
            ThrowMsg(CynaraException::InvalidParam, msg);
        case CYNARA_API_SERVICE_NOT_AVAILABLE:
            ThrowMsg(CynaraException::ServiceNotAvailable, msg);
        default:
            ThrowMsg(CynaraException::UnknownError, msg);
    }
}

CynaraAdmin::CynaraAdmin()
{
    checkCynaraError(
        cynara_admin_initialize(&m_CynaraAdmin),
        "Cannot connect to Cynara administrative interface.");
}

CynaraAdmin::~CynaraAdmin()
{
    cynara_admin_finish(m_CynaraAdmin);
}

CynaraAdmin &CynaraAdmin::getInstance()
{
    static CynaraAdmin cynaraAdmin;
    return cynaraAdmin;
}

void CynaraAdmin::SetPolicies(const std::vector<CynaraAdminPolicy> &policies)
{
    std::vector<const struct cynara_admin_policy *> pp_policies(policies.size() + 1);

    LogDebug("Sending " << policies.size() << " policies to Cynara");
    for (std::size_t i = 0; i < policies.size(); ++i) {
        pp_policies[i] = static_cast<const struct cynara_admin_policy *>(&policies[i]);
        LogDebug("policies[" << i << "] = {" <<
            ".bucket = " << pp_policies[i]->bucket << ", " <<
            ".client = " << pp_policies[i]->client << ", " <<
            ".user = " << pp_policies[i]->user << ", " <<
            ".privilege = " << pp_policies[i]->privilege << ", " <<
            ".result = " << pp_policies[i]->result << ", " <<
            ".result_extra = " << pp_policies[i]->result_extra << "}");
    }

    pp_policies[policies.size()] = nullptr;

    checkCynaraError(
        cynara_admin_set_policies(m_CynaraAdmin, pp_policies.data()),
        "Error while updating Cynara policy.");
}

void CynaraAdmin::UpdatePackagePolicy(
    const std::string &label,
    const std::string &user,
    const std::vector<std::string> &oldPrivileges,
    const std::vector<std::string> &newPrivileges)
{
    CynaraAdmin cynaraAdmin;
    std::vector<CynaraAdminPolicy> policies;

    // Perform sort-merge join on oldPrivileges and newPrivileges.
    // Assume that they are already sorted and without duplicates.
    auto oldIter = oldPrivileges.begin();
    auto newIter = newPrivileges.begin();

    while (oldIter != oldPrivileges.end() && newIter != newPrivileges.end()) {
        int compare = oldIter->compare(*newIter);
        if (compare == 0) {
            LogDebug("(user = " << user << " label = " << label << ") " <<
                "keeping privilege " << *newIter);
            ++oldIter;
            ++newIter;
            continue;
        } else if (compare < 0) {
            LogDebug("(user = " << user << " label = " << label << ") " <<
                "removing privilege " << *oldIter);
            policies.push_back(CynaraAdminPolicy(label, user, *oldIter,
                    CynaraAdminPolicy::Operation::Delete));
            ++oldIter;
        } else {
            LogDebug("(user = " << user << " label = " << label << ") " <<
                "adding privilege " << *newIter);
            policies.push_back(CynaraAdminPolicy(label, user, *newIter,
                    CynaraAdminPolicy::Operation::Allow));
            ++newIter;
        }
    }

    for (; oldIter != oldPrivileges.end(); ++oldIter) {
        LogDebug("(user = " << user << " label = " << label << ") " <<
            "removing privilege " << *oldIter);
        policies.push_back(CynaraAdminPolicy(label, user, *oldIter,
                    CynaraAdminPolicy::Operation::Delete));
    }

    for (; newIter != newPrivileges.end(); ++newIter) {
        LogDebug("(user = " << user << " label = " << label << ") " <<
            "adding privilege " << *newIter);
        policies.push_back(CynaraAdminPolicy(label, user, *newIter,
                    CynaraAdminPolicy::Operation::Allow));
    }

    cynaraAdmin.SetPolicies(policies);
}

Cynara::Cynara()
{
    checkCynaraError(
        cynara_initialize(&m_Cynara, nullptr),
        "Cannot connect to Cynara policy interface.");
}

Cynara::~Cynara()
{
    cynara_finish(m_Cynara);
}

Cynara &Cynara::getInstance()
{
    static Cynara cynara;
    return cynara;
}

bool Cynara::check(const std::string &label, const std::string &privilege,
        const std::string &user, const std::string &session)
{
    return checkCynaraError(
        cynara_check(m_Cynara,
            label.c_str(), session.c_str(), user.c_str(), privilege.c_str()),
        "Cannot check permission with Cynara.");
}

} // namespace SecurityManager