/*
 *  Copyright (c) 2014-2016 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <unordered_set>
#include "cynara.h"

#include <dpl/log/log.h>
#include <dpl/errno_string.h>
#include <config.h>
#include <utils.h>

namespace SecurityManager {

/**
 * Rules for apps and users are organized into set of buckets stored in Cynara.
 * Bucket is set of rules (app, uid, privilege) -> (DENY, ALLOW, BUCKET, ...).
 *  |------------------------|
 *  |      <<allow>>         |
 *  |   PRIVACY_MANAGER      |
 *  |------------------------|
 *  |  A    U   P      policy|
 *  |------------------------|
 *  | app1 uid1 priv1  DENY  |
 *  |  *   uid2 priv2  DENY  |
 *  |  * * *      Bucket:MAIN|
 *  |------------------------|
 *
 * For details about buckets see Cynara documentation.
 *
 * Security Manager currently defines 8 buckets:
 * - PRIVACY_MANAGER - first bucket during search (which is actually default bucket
 *   with empty string as id). If user specifies his preference then required rule
 *   is created here.
 * - MAIN            - holds rules denied by manufacturer, redirects to MANIFESTS
 *   bucket and holds entries for each user pointing to User Type
 *   specific buckets
 * - MANIFESTS       - stores rules needed by installed apps (from package
 *   manifest)
 * - USER_TYPE_ADMIN
 * - USER_TYPE_SYSTEM
 * - USER_TYPE_NORMAL
 * - USER_TYPE_SECURITY
 * - USER_TYPE_GUEST - they store privileges from templates for apropriate
 *   user type. ALLOW rules only.
 * - ADMIN           - stores custom rules introduced by device administrator.
 *   Ignored if no matching rule found.
 *
 * Below is basic layout of buckets:
 *
 *  |------------------------|
 *  |      <<allow>>         |
 *  |   PRIVACY_MANAGER      |
 *  |                        |
 *  |  * * *      Bucket:MAIN|                         |------------------|
 *  |------------------------|                         |      <<deny>>    |
 *             |                                    |->|     MANIFESTS    |
 *             -----------------                    |  |                  |
 *                             |                    |  |------------------|
 *                             V                    |
 *                     |------------------------|   |
 *                     |       <<deny>>         |---|
 *                     |         MAIN           |
 * |---------------|   |                        |     |-------------------|
 * |    <<deny>>   |<--| * * *  Bucket:MANIFESTS|---->|      <<deny>>     |
 * | USER_TYPE_SYST|   |------------------------|     |  USER_TYPE_NORMAL |
 * |               |        |       |      |          |                   |
 * |---------------|        |       |      |          |-------------------|
 *        |                 |       |      |                    |
 *        |                 V       |      V                    |
 *        |      |---------------|  |   |---------------|       |
 *        |      |    <<deny>>   |  |   |    <<deny>>   |       |
 *        |      |USER_TYPE_GUEST|  |   |USER_TYPE_ADMIN|       |
 *        |      |               |  |   |               |       |
 *        |      |---------------|  |   |---------------|       |
 *        |           |             V               |           |
 *        |           |     |------------------|    |           |
 *        |           |     |     <<deny>>     |    |           |
 *        |           |     |USER_TYPE_SECURITY|    |           |
 *        |           |     |                  |    |           |
 *        |           |     |------------------|    |           |
 *        |           |             |               |           |
 *        |           |             |               |           |
 *        |           |             |               |           |
 *        |           |             V               |           |
 *        |           |    |------------------|     |           |
 *        |           |--->|     <<none>>     |<----|           |
 *        |                |       ADMIN      |                 |
 *        |--------------->|                  |<----------------|
 *                         |------------------|
 *
 */
CynaraAdmin::BucketsMap CynaraAdmin::Buckets =
{
    { Bucket::PRIVACY_MANAGER, std::string(CYNARA_ADMIN_DEFAULT_BUCKET)},
    { Bucket::MAIN, std::string("MAIN")},
    { Bucket::USER_TYPE_ADMIN, std::string("USER_TYPE_ADMIN")},
    { Bucket::USER_TYPE_NORMAL, std::string("USER_TYPE_NORMAL")},
    { Bucket::USER_TYPE_SECURITY, std::string("USER_TYPE_SECURITY")},
    { Bucket::USER_TYPE_GUEST, std::string("USER_TYPE_GUEST") },
    { Bucket::USER_TYPE_SYSTEM, std::string("USER_TYPE_SYSTEM")},
    { Bucket::ADMIN, std::string("ADMIN")},
    { Bucket::MANIFESTS, std::string("MANIFESTS")},
};

CynaraAdminPolicy::CynaraAdminPolicy()
{
    this->client = nullptr;
    this->user = nullptr;
    this->privilege = nullptr;
    this->bucket = nullptr;
    this->result = CYNARA_ADMIN_NONE;
    this->result_extra = nullptr;
}

CynaraAdminPolicy::CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, int operation,
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

    this->result = operation;
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

CynaraAdminPolicy& CynaraAdminPolicy::operator=(CynaraAdminPolicy &&that)
{
    if (this != &that) {
        free(this->bucket);
        free(this->client);
        free(this->user);
        free(this->privilege);
        free(this->result_extra);

        this->bucket = that.bucket;
        this->client = that.client;
        this->user = that.user;
        this->privilege = that.privilege;
        this->result_extra = that.result_extra;
        this->result = that.result;

        that.bucket = nullptr;
        that.client = nullptr;
        that.user = nullptr;
        that.privilege = nullptr;
        that.result_extra = nullptr;
    };

    return *this;
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
        case CYNARA_API_MAX_PENDING_REQUESTS:
            ThrowMsg(CynaraException::MaxPendingRequests, msg);
        case CYNARA_API_OUT_OF_MEMORY:
            ThrowMsg(CynaraException::OutOfMemory, msg);
        case CYNARA_API_INVALID_PARAM:
            ThrowMsg(CynaraException::InvalidParam, msg);
        case CYNARA_API_SERVICE_NOT_AVAILABLE:
            ThrowMsg(CynaraException::ServiceNotAvailable, msg);
        case CYNARA_API_METHOD_NOT_SUPPORTED:
            ThrowMsg(CynaraException::MethodNotSupported, msg);
        case CYNARA_API_OPERATION_NOT_ALLOWED:
            ThrowMsg(CynaraException::OperationNotAllowed, msg);
        case CYNARA_API_OPERATION_FAILED:
            ThrowMsg(CynaraException::OperationFailed, msg);
        case CYNARA_API_BUCKET_NOT_FOUND:
            ThrowMsg(CynaraException::BucketNotFound, msg);
        case CYNARA_API_CONFIGURATION_ERROR:
            ThrowMsg(CynaraException::ConfigurationError, msg);
        case CYNARA_API_INVALID_COMMANDLINE_PARAM:
            ThrowMsg(CynaraException::InvalidCommandlineParam, msg);
        case CYNARA_API_BUFFER_TOO_SHORT:
            ThrowMsg(CynaraException::BufferTooShort, msg);
        case CYNARA_API_DATABASE_CORRUPTED:
            ThrowMsg(CynaraException::DatabaseCorrupted, msg);
        default:
            ThrowMsg(CynaraException::UnknownError, msg);
    }
}

CynaraAdmin::TypeToDescriptionMap CynaraAdmin::TypeToDescription;
CynaraAdmin::DescriptionToTypeMap CynaraAdmin::DescriptionToType;

CynaraAdmin::CynaraAdmin()
    : m_policyDescriptionsInitialized(false)
{
    checkCynaraError(
        cynara_admin_initialize(&m_CynaraAdmin),
        "Cannot connect to Cynara administrative interface.");
}

CynaraAdmin::~CynaraAdmin()
{
    cynara_admin_finish(m_CynaraAdmin);
}

void CynaraAdmin::SetPolicies(const std::vector<CynaraAdminPolicy> &policies)
{
    if (policies.empty()) {
        LogDebug("no policies to set in Cynara.");
        return;
    }

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

void CynaraAdmin::UpdateAppPolicy(
    const std::string &label,
    const std::string &user,
    const std::vector<std::string> &privileges,
    std::function <bool(const std::string &, const std::string &)> isPrivacy)
{
    auto calcPolicies = [&](
        const std::string &user,
        const std::vector<std::string> &privileges,
        const std::string &bucket,
        int policyToSet,
        std::vector<CynaraAdminPolicy> &policies)
    {
        std::vector<CynaraAdminPolicy> oldPolicies;
        std::unordered_set<std::string> privilegesSet(privileges.begin(),
                                                      privileges.end());
        ListPolicies(bucket, label, user,
                                               CYNARA_ADMIN_ANY, oldPolicies);

        // Compare previous policies with set of new requested privileges
        for (auto &policy : oldPolicies) {
            if (privilegesSet.erase(policy.privilege)) {
                // privilege was found and removed from the set, keeping policy
                LogDebug("(user = " << user << " label = " << label << ") " <<
                         "keeping privilege " << policy.privilege);
            } else {
                // privilege was not found in the set, deleting policy
                policy.result = static_cast<int>(CynaraAdminPolicy::Operation::Delete);
                LogDebug("(user = " << user << " label = " << label << ") " <<
                        "removing privilege " << policy.privilege);
            }
            policies.push_back(std::move(policy));
        }

        // Add policies for privileges that weren't previously enabled
        // Those that were previously enabled are now removed from privilegesSet
        for (const auto &privilege : privilegesSet) {
            LogDebug("(user = " << user << " label = " << label << ") " <<
                     "adding privilege " << privilege);
            policies.push_back(CynaraAdminPolicy(label, user, privilege, policyToSet, bucket));
        }
    };

    std::vector<CynaraAdminPolicy> policies;

    // 1st, performing operation on MANIFESTS bucket
    calcPolicies(user, privileges, Buckets.at(Bucket::MANIFESTS),
        static_cast<int>(CynaraAdminPolicy::Operation::Allow),
        policies);

    if (Config::IS_ASKUSER_ENABLED) {
        try {
            int askUserPolicy = convertToPolicyType(Config::PRIVACY_POLICY_DESC);

            std::vector<std::string> privacyPrivileges;
            for (auto &p : privileges)
                if (isPrivacy(label, p))
                    privacyPrivileges.push_back(p);

            // 2nd, performing operation on PRIVACY_MANAGER bucket for all affected users
            if (user == CYNARA_ADMIN_WILDCARD) {
                // perform bucket setting for all users in the system, app is installed for everyone
                std::vector<uid_t> users;
                ListUsers(users);
                for (uid_t id : users) {
                    calcPolicies(std::to_string(id), privacyPrivileges,
                                 Buckets.at(Bucket::PRIVACY_MANAGER),
                                 askUserPolicy, policies);
                }
            } else {
                // local single user installation, do it only for that particular user
                calcPolicies(user, privacyPrivileges, Buckets.at(Bucket::PRIVACY_MANAGER),
                             askUserPolicy, policies);
            }
        } catch (const std::out_of_range&) {
            LogDebug("Unknown policy level: " << Config::PRIVACY_POLICY_DESC);
        };
    }
    SetPolicies(policies);
}

void CynaraAdmin::GetAppPolicy(const std::string &label, const std::string &user,
        std::vector<std::string> &privileges)
{
    std::vector<CynaraAdminPolicy> policies;
    ListPolicies(
        CynaraAdmin::Buckets.at(Bucket::MANIFESTS),
        label, user, CYNARA_ADMIN_ANY, policies);

    for (auto &policy : policies) {
        std::string privilege = policy.privilege;
        if (privilege.compare(CYNARA_ADMIN_WILDCARD))
            privileges.push_back(std::move(privilege));
    }
}

void CynaraAdmin::UserInit(uid_t uid, security_manager_user_type userType,
        std::function <bool(const std::string &, const std::string &)> isPrivacy)
{
    Bucket bucket;
    std::vector<CynaraAdminPolicy> policies;
    std::string userStr = std::to_string(uid);

    switch (userType) {
        case SM_USER_TYPE_SYSTEM:
            bucket = Bucket::USER_TYPE_SYSTEM;
            break;
        case SM_USER_TYPE_ADMIN:
            bucket = Bucket::USER_TYPE_ADMIN;
            break;
        case SM_USER_TYPE_GUEST:
            bucket = Bucket::USER_TYPE_GUEST;
            break;
        case SM_USER_TYPE_NORMAL:
            bucket = Bucket::USER_TYPE_NORMAL;
            break;
        case SM_USER_TYPE_SECURITY:
            bucket = Bucket::USER_TYPE_SECURITY;
            break;
        case SM_USER_TYPE_ANY:
        case SM_USER_TYPE_NONE:
        default:
            ThrowMsg(CynaraException::InvalidParam, "User type incorrect");
    }

    policies.push_back(CynaraAdminPolicy(CYNARA_ADMIN_WILDCARD,
                                            userStr,
                                            CYNARA_ADMIN_WILDCARD,
                                            Buckets.at(bucket),
                                            Buckets.at(Bucket::MAIN)));

    if (Config::IS_ASKUSER_ENABLED) {
        try{
            // for each global app: retrieve its privacy-related privileges and set
            // their policy in PRIVACY_MANAGER bucket to "Ask user"

            int askUserPolicy = convertToPolicyType(Config::PRIVACY_POLICY_DESC);

            std::vector<CynaraAdminPolicy> appPolicies;
            ListPolicies(CynaraAdmin::Buckets.at(Bucket::MANIFESTS),
                                                    CYNARA_ADMIN_ANY, CYNARA_ADMIN_WILDCARD,
                                                    CYNARA_ADMIN_ANY, appPolicies);

            for (CynaraAdminPolicy &policy : appPolicies)
                if (isPrivacy(policy.client, policy.privilege))
                    policies.push_back(CynaraAdminPolicy(policy.client,
                    userStr,
                    policy.privilege,
                    askUserPolicy,
                    Buckets.at(Bucket::PRIVACY_MANAGER)));
        } catch (const std::out_of_range&) {
            LogDebug("Unknown policy level: " << Config::PRIVACY_POLICY_DESC);
        };
    }

    SetPolicies(policies);
}

void CynaraAdmin::ListUsers(std::vector<uid_t> &listOfUsers)
{
    std::vector<CynaraAdminPolicy> tmpListOfUsers;
    ListPolicies(
        CynaraAdmin::Buckets.at(Bucket::MAIN),
        CYNARA_ADMIN_WILDCARD,
        CYNARA_ADMIN_ANY,
        CYNARA_ADMIN_WILDCARD,
        tmpListOfUsers);

    for (const auto &tmpUser : tmpListOfUsers) {
        std::string user = tmpUser.user;
        if (!user.compare(CYNARA_ADMIN_WILDCARD))
            continue;
        try {
            listOfUsers.push_back(std::stoul(user));
        } catch (std::invalid_argument &e) {
            LogError("Invalid UID: " << e.what());
            continue;
        };
    };
    LogDebug("Found users: " << listOfUsers.size());
};

void CynaraAdmin::UserRemove(uid_t uid)
{
    std::vector<CynaraAdminPolicy> policies;
    std::string user = std::to_string(static_cast<unsigned int>(uid));

    EmptyBucket(Buckets.at(Bucket::PRIVACY_MANAGER),true,
            CYNARA_ADMIN_ANY, user, CYNARA_ADMIN_ANY);
}

security_manager_user_type CynaraAdmin::GetUserType(uid_t uid)
{
    std::string uidStr = std::to_string(uid);
    std::vector<CynaraAdminPolicy> tmpListOfUsers;
    ListPolicies(
            CynaraAdmin::Buckets.at(Bucket::MAIN),
            CYNARA_ADMIN_WILDCARD,
            uidStr,
            CYNARA_ADMIN_WILDCARD,
            tmpListOfUsers);

    if (tmpListOfUsers.size() != 1) {
        // < 1 -> user not found
        // > 1 -> impossible
        return SM_USER_TYPE_NONE;
    }

    auto metadata = tmpListOfUsers.at(0).result_extra;

    if (metadata == Buckets.at(Bucket::USER_TYPE_NORMAL))
        return SM_USER_TYPE_NORMAL;
    else if (metadata == Buckets.at(Bucket::USER_TYPE_ADMIN))
        return SM_USER_TYPE_ADMIN;
    else if (metadata == Buckets.at(Bucket::USER_TYPE_GUEST))
        return SM_USER_TYPE_GUEST;
    else if (metadata == Buckets.at(Bucket::USER_TYPE_SYSTEM))
        return SM_USER_TYPE_SYSTEM;
    else if (metadata == Buckets.at(Bucket::USER_TYPE_SECURITY))
        return SM_USER_TYPE_SECURITY;
    else    // improperly configured
        return SM_USER_TYPE_NONE;
};

void CynaraAdmin::ListPolicies(
    const std::string &bucket,
    const std::string &label,
    const std::string &user,
    const std::string &privilege,
    std::vector<CynaraAdminPolicy> &policies)
{
    struct cynara_admin_policy ** pp_policies = nullptr;

    checkCynaraError(
        cynara_admin_list_policies(m_CynaraAdmin, bucket.c_str(), label.c_str(),
            user.c_str(), privilege.c_str(), &pp_policies),
        "Error while getting list of policies for bucket: " + bucket);

    for (std::size_t i = 0; pp_policies[i] != nullptr; i++) {
        policies.push_back(std::move(*static_cast<CynaraAdminPolicy*>(pp_policies[i])));

        free(pp_policies[i]);
    }

    free(pp_policies);

}

void CynaraAdmin::EmptyBucket(const std::string &bucketName, bool recursive, const std::string &client,
    const std::string &user, const std::string &privilege)
{
    checkCynaraError(
        cynara_admin_erase(m_CynaraAdmin, bucketName.c_str(), static_cast<int>(recursive),
            client.c_str(), user.c_str(), privilege.c_str()),
        "Error while emptying bucket: " + bucketName + ", filter (C, U, P): " +
            client + ", " + user + ", " + privilege);
}

void CynaraAdmin::FetchCynaraPolicyDescriptions(bool forceRefresh)
{
    struct cynara_admin_policy_descr **descriptions = nullptr;

    if (!forceRefresh && m_policyDescriptionsInitialized)
        return;

    // fetch
    checkCynaraError(
        cynara_admin_list_policies_descriptions(m_CynaraAdmin, &descriptions),
        "Error while getting list of policies descriptions from Cynara.");

    if (descriptions[0] == nullptr) {
        LogError("Fetching policies levels descriptions from Cynara returned empty list. "
                "There should be at least 2 entries - Allow and Deny");
        return;
    }

    // reset the state
    m_policyDescriptionsInitialized = false;
    DescriptionToType.clear();
    TypeToDescription.clear();

    // extract strings
    for (int i = 0; descriptions[i] != nullptr; i++) {
        std::string descriptionName(descriptions[i]->name);

        DescriptionToType[descriptionName] = descriptions[i]->result;
        TypeToDescription[descriptions[i]->result] = std::move(descriptionName);

        free(descriptions[i]->name);
        free(descriptions[i]);
    }

    free(descriptions);

    m_policyDescriptionsInitialized = true;
}

void CynaraAdmin::ListPoliciesDescriptions(std::vector<std::string> &policiesDescriptions)
{
    FetchCynaraPolicyDescriptions(false);

    for (const auto &it : TypeToDescription)
        policiesDescriptions.push_back(it.second);
}

std::string CynaraAdmin::convertToPolicyDescription(const int policyType, bool forceRefresh)
{
    FetchCynaraPolicyDescriptions(forceRefresh);

    return TypeToDescription.at(policyType);
}

int CynaraAdmin::convertToPolicyType(const std::string &policy, bool forceRefresh)
{
    FetchCynaraPolicyDescriptions(forceRefresh);

    return DescriptionToType.at(policy);
}

void CynaraAdmin::Check(const std::string &label, const std::string &user, const std::string &privilege,
    const std::string &bucket, int &result, std::string &resultExtra, const bool recursive)
{
    char *resultExtraCstr = nullptr;

    checkCynaraError(
        cynara_admin_check(m_CynaraAdmin, bucket.c_str(), recursive, label.c_str(),
            user.c_str(), privilege.c_str(), &result, &resultExtraCstr),
        "Error while asking cynara admin API for permission for app label: " + label + ", user: "
            + user + " privilege: " + privilege + " bucket: " + bucket);

    if (resultExtraCstr == nullptr)
        resultExtra = "";
    else {
        resultExtra = std::string(resultExtraCstr);
        free(resultExtraCstr);
    }
}

int CynaraAdmin::GetPrivilegeManagerCurrLevel(const std::string &label, const std::string &user,
        const std::string &privilege)
{
    int result;
    std::string resultExtra;

    Check(label, user, privilege, Buckets.at(Bucket::PRIVACY_MANAGER), result, resultExtra, true);

    return result;
}

int CynaraAdmin::GetPrivilegeManagerMaxLevel(const std::string &label, const std::string &user,
        const std::string &privilege)
{
    int result;
    std::string resultExtra;

    Check(label, user, privilege, Buckets.at(Bucket::MAIN), result, resultExtra, true);

    return result;
}

Cynara::Cynara()
{
    int ret;

    ret = eventfd(0, 0);
    if (ret == -1) {
        LogError("Error while creating eventfd: " << GetErrnoString(errno));
        ThrowMsg(CynaraException::UnknownError, "Error while creating eventfd");
    }

    // Poll the eventfd for reading
    pollFds[0].fd = ret;
    pollFds[0].events = POLLIN;

    // Temporary, will be replaced by cynara fd when available
    pollFds[1].fd = pollFds[0].fd;
    pollFds[1].events = 0;

    cynara_async_configuration *p_conf = nullptr;
    checkCynaraError(cynara_async_configuration_create(&p_conf),
                     "Cannot create cynara async configuration");
    auto confPtr = makeUnique(p_conf, cynara_async_configuration_destroy);

    checkCynaraError(cynara_async_configuration_set_cache_size(p_conf, CACHE_SIZE),
            "Cannot set cynara async configuration cache size");
    checkCynaraError(
        cynara_async_initialize(&cynara, p_conf, &Cynara::statusCallback, &(pollFds[1])),
        "Cannot connect to Cynara policy interface.");

    thread = std::thread(&Cynara::run, this);
}

Cynara::~Cynara()
{
    LogDebug("Sending terminate event to Cynara thread");
    terminate.store(true);
    threadNotifyPut();
    thread.join();

    // Critical section
    std::lock_guard<std::mutex> guard(mutex);
    cynara_async_finish(cynara);
}

void Cynara::threadNotifyPut()
{
    int ret = eventfd_write(pollFds[0].fd, 1);
    if (ret == -1)
        LogError("Unexpected error while writing to eventfd: " << GetErrnoString(errno));
}

void Cynara::threadNotifyGet()
{
    eventfd_t value;
    int ret = eventfd_read(pollFds[0].fd, &value);
    if (ret == -1)
        LogError("Unexpected error while reading from eventfd: " << GetErrnoString(errno));
}

void Cynara::statusCallback(int oldFd, int newFd, cynara_async_status status,
    void *ptr)
{
    auto cynaraFd = static_cast<struct pollfd *>(ptr);

    LogDebug("Cynara status callback. " <<
        "Status = " << status << ", oldFd = " << oldFd << ", newFd = " << newFd);

    if (newFd == -1) {
        cynaraFd->events = 0;
    } else {
        cynaraFd->fd = newFd;

        switch (status) {
        case CYNARA_STATUS_FOR_READ:
            cynaraFd->events = POLLIN;
            break;

        case CYNARA_STATUS_FOR_RW:
            cynaraFd->events = POLLIN | POLLOUT;
            break;
        }
    }
}

void Cynara::responseCallback(cynara_check_id checkId,
    cynara_async_call_cause cause, int response, void *ptr)
{
    LogDebug("Response for received for Cynara check id: " << checkId);

    auto promise = static_cast<std::promise<bool>*>(ptr);

    switch (cause) {
    case CYNARA_CALL_CAUSE_ANSWER:
        LogDebug("Cynara cause: ANSWER: " << response);
        promise->set_value(response == CYNARA_API_ACCESS_ALLOWED);
        break;

    case CYNARA_CALL_CAUSE_CANCEL:
        LogDebug("Cynara cause: CANCEL");
        promise->set_value(CYNARA_API_ACCESS_DENIED);
        break;

    case CYNARA_CALL_CAUSE_FINISH:
        LogDebug("Cynara cause: FINISH");
        promise->set_value(CYNARA_API_ACCESS_DENIED);
        break;

    case CYNARA_CALL_CAUSE_SERVICE_NOT_AVAILABLE:
        LogError("Cynara cause: SERVICE_NOT_AVAILABLE");

        try {
            ThrowMsg(CynaraException::ServiceNotAvailable,
                "Cynara service not available");
        } catch (...) {
            promise->set_exception(std::current_exception());
        }
        break;
    }
}

void Cynara::run()
{
    LogInfo("Cynara thread started");
    while (true) {
        int ret = poll(pollFds, 2, -1);
        if (ret == -1) {
            if (errno != EINTR)
                LogError("Unexpected error returned by poll: " << GetErrnoString(errno));
            continue;
        }

        // Check eventfd for termination signal
        if (pollFds[0].revents) {
            threadNotifyGet();
            if (terminate.load()) {
                LogInfo("Cynara thread terminated");
                return;
            }
        }

        // Check if Cynara fd is ready for processing
        try {
            if (pollFds[1].revents) {
                // Critical section
                std::lock_guard<std::mutex> guard(mutex);

                checkCynaraError(cynara_async_process(cynara),
                    "Unexpected error returned by cynara_async_process");
            }
        } catch (const CynaraException::Base &e) {
            LogError("Error while processing Cynara events: " << e.DumpToString());
        }
    }
}

bool Cynara::check(const std::string &label, const std::string &privilege,
        const std::string &user, const std::string &session)
{
    LogDebug("check: client = " << label << ", user = " << user <<
        ", privilege = " << privilege << ", session = " << session);

    std::promise<bool> promise;
    auto future = promise.get_future();

    // Critical section
    {
        std::lock_guard<std::mutex> guard(mutex);

        int ret = cynara_async_check_cache(cynara,
            label.c_str(), session.c_str(), user.c_str(), privilege.c_str());

        if (ret != CYNARA_API_CACHE_MISS)
            return checkCynaraError(ret, "Error while checking Cynara cache");

        LogDebug("Cynara cache miss");

        cynara_check_id check_id;
        checkCynaraError(
            cynara_async_create_request(cynara,
                label.c_str(), session.c_str(), user.c_str(), privilege.c_str(),
                &check_id, &Cynara::responseCallback, &promise),
            "Cannot check permission with Cynara.");

        threadNotifyPut();
        LogDebug("Waiting for response to Cynara query id " << check_id);
    }

    return future.get();
}

} // namespace SecurityManager
