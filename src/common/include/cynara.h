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
 * @file        cynara.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Wrapper class for Cynara interface
 */

#pragma once

#include <cynara-client-async.h>
#include <cynara-admin.h>
#include <dpl/exception.h>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <future>

#include <poll.h>
#include <sys/eventfd.h>

#include "security-manager.h"

namespace SecurityManager {

enum class Bucket
{
    PRIVACY_MANAGER,
    MAIN,
    USER_TYPE_ADMIN,
    USER_TYPE_NORMAL,
    USER_TYPE_SECURITY,
    USER_TYPE_GUEST,
    USER_TYPE_SYSTEM,
    ADMIN,
    MANIFESTS
};

class CynaraException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, MaxPendingRequests)
    DECLARE_EXCEPTION_TYPE(Base, OutOfMemory)
    DECLARE_EXCEPTION_TYPE(Base, InvalidParam)
    DECLARE_EXCEPTION_TYPE(Base, ServiceNotAvailable)
    DECLARE_EXCEPTION_TYPE(Base, MethodNotSupported)
    DECLARE_EXCEPTION_TYPE(Base, OperationNotAllowed)
    DECLARE_EXCEPTION_TYPE(Base, OperationFailed)
    DECLARE_EXCEPTION_TYPE(Base, BucketNotFound)
    DECLARE_EXCEPTION_TYPE(Base, UnknownError)
    DECLARE_EXCEPTION_TYPE(Base, ConfigurationError)
    DECLARE_EXCEPTION_TYPE(Base, InvalidCommandlineParam)
    DECLARE_EXCEPTION_TYPE(Base, BufferTooShort)
    DECLARE_EXCEPTION_TYPE(Base, DatabaseCorrupted)
};

struct CynaraAdminPolicy : cynara_admin_policy
{
    enum class Operation {
        Deny = CYNARA_ADMIN_DENY,
        Allow = CYNARA_ADMIN_ALLOW,
        Delete = CYNARA_ADMIN_DELETE,
        Bucket = CYNARA_ADMIN_BUCKET,
    };

    CynaraAdminPolicy();

    CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, int operation,
        const std::string &bucket = std::string(CYNARA_ADMIN_DEFAULT_BUCKET));

    CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, const std::string &goToBucket,
        const std::string &bucket = std::string(CYNARA_ADMIN_DEFAULT_BUCKET));

    /* Don't provide copy constructor, it would cause pointer trouble. */
    CynaraAdminPolicy(const CynaraAdminPolicy &that) = delete;

    /* Move constructor is the way to go. */
    CynaraAdminPolicy(CynaraAdminPolicy &&that);
    CynaraAdminPolicy& operator=(CynaraAdminPolicy &&that);

    ~CynaraAdminPolicy();
};

class CynaraAdmin
{
public:

    typedef std::map<Bucket, const std::string > BucketsMap;
    static BucketsMap Buckets;

    typedef  std::map<int, std::string> TypeToDescriptionMap;
    typedef  std::map<std::string, int> DescriptionToTypeMap;

    virtual ~CynaraAdmin();
    CynaraAdmin();

    /**
     * Update Cynara policies.
     * Caller must have permission to access Cynara administrative socket.
     *
     * @param policies vector of CynaraAdminPolicy objects to send to Cynara
     */
    void setPolicies(const std::vector<CynaraAdminPolicy> &policies);

    /**
     * Update Cynara policies for the application and the user.
     * Difference will be calculated, removing old unneeded privileges and
     * adding new, previously not enabled privileges.
     * Caller must have permission to access Cynara administrative socket.
     *
     * @param label application Smack label
     * @param global true if it's a global or preloaded installation
     * @param uid user identifier
     * @param privileges currently enabled privileges
     */
    void updateAppPolicy(const std::string &label, bool global, uid_t uid,
        const std::vector<std::string> &privileges);

    /**
     * Fetch Cynara policies for the application and the user.
     * Caller must have permission to access Cynara administrative socket.
     *
     * @param[in] label application Smack label
     * @param[in] user user identifier
     * @param[out] privileges currently enabled privileges
     */
    void getAppPolicy(const std::string &label, const std::string &user,
        std::vector<std::string> &privileges);

    /**
     * Depending on user type, create link between MAIN bucket and appropriate
     * USER_TYPE_* bucket for newly added user uid to apply permissions for that
     * user type.
     * @throws CynaraException::InvalidParam.
     *
     * @param uid new user uid
     * @param userType type as enumerated in security-manager.h
     */
    void userInit(uid_t uid, security_manager_user_type userType);

    /**
     * List all users registered in Cynara
     *
     * @param listOfUsers empty vector for list of users
     */
    void listUsers(std::vector<uid_t> &listOfUsers);

    /**
     * Removes all entries for a user from cynara database
     *
     * @param uid removed user uid
     */
    void userRemove(uid_t uid);

    /**
     * Returns user type of given uid
     *
     * @param[in] uid uid to check
     *
     * @return security_manager_user_type for given uid or SM_USER_TYPE_NONE if user not found
     *
     */
    security_manager_user_type getUserType(uid_t uid);

    /**
     * List Cynara policies that match selected criteria in given bucket.
     *
     * @param bucketName name of the bucket to search policies in
     * @param label string with label of app to match in search
     * @param user user string to match in search
     * @param privilege privilege string to match in search
     * @param policies empty vector for results of policies filtering.
     *
     */
    void listPolicies(const std::string &bucketName,
        const std::string &label,
        const std::string &user,
        const std::string &privilege,
        std::vector<CynaraAdminPolicy> &policies);

    /**
     * Wrapper for Cynara API function cynara_admin_list_policies_descriptions.
     * It collects all policies descriptions, extracts names
     * of policies and returns as std strings. Caller is responsible for clearing
     * vector passed as argument.
     *
     * @param policiesDescriptions empty vector for policies descriptions.
     */
    void listPoliciesDescriptions(std::vector<std::string> &policiesDescriptions);

    /**
     * Function translates internal Cynara policy type integer to string
     * description. Descriptions are retrieved from Cynara using
     * ListPoliciesDescriptions() function. Caller can force refetching of
     * descriptions list from Cynara on each call.
     *
     * @throws std::out_of_range
     *
     * @param policyType Cynara policy result type.
     * @param forceRefresh switch to force refetching of descriptions from Cynara.
     */
    std::string convertToPolicyDescription(const int policyType, bool forceRefresh = false);

    /**
     * Function translates Cynara policy result string
     * description to internal Cynara policy type integer.
     * Descriptions are retrieved from Cynara using
     * ListPoliciesDescriptions() function. Caller can force refetching of
     * descriptions list from Cynara on each call.
     *
     * @throws std::out_of_range
     *
     * @param policy Cynara policy result string description.
     * @param forceRefresh switch to force refetching of descriptions from Cynara.
     */
    int convertToPolicyType(const std::string &policy, bool forceRefresh = false);

    /**
     * Ask Cynara for permission starting the search at specified bucket.
     * Essentialy a wrapper on cynara_admin_check.
     *
     * @param label application Smack label
     * @param privilege privilege string to match in search
     * @param user user string to match in search
     * @param bucket name of the bucket to search policies in
     * @param result integer to return policy result
     * @param resultExtra string to return additional information about policy
     *        result. If result is Bucket then resultExtra is the name of
     *        bucket.
     * @param recursive flag to indicate if check should be done recursively in
     *        all buckets linked with bucket provided
     */
    void check(const std::string &label,
        const std::string &user,
        const std::string &privilege,
        const std::string &bucket,
        int &result,
        std::string &resultExtra,
        const bool recursive);

    /**
     * Get current policy level for privilege-manager functionality
     * Returns current policy value for given application, user and privilege
     * identifiers.
     *
     * @param label application Smack label
     * @param user user identifier (uid)
     * @param privilege privilege identifier
     * @return current policy value
     */
    int getPrivilegeManagerCurrLevel(const std::string &label, const std::string &user,
        const std::string &privilege);

    /**
     * Get maximum policy level for privilege-manager functionality
     * Returns maximum possible policy value for given application, user and privilege
     * identifiers. The maximum limit is imposed by other policy settings that are
     * currently in place.
     *
     * @param label application Smack label
     * @param user user identifier (uid)
     * @param privilege privilege identifier
     * @return maximum policy value for PRIVACY_MANAGER bucket
     */
    int getPrivilegeManagerMaxLevel(const std::string &label, const std::string &user,
        const std::string &privilege);

private:
    /**
     * Empty bucket using filter - matching rules will be removed
     *
     * @param bucketName name of the bucket to be emptied
     * @param recursive flag to remove privileges recursively
     * @param client client name
     * @param user user name
     * @param privilege privilege name
     */
    void emptyBucket(const std::string &bucketName, bool recursive,
        const std::string &client, const std::string &user, const std::string &privilege);

    /**
     * Get Cynara policies result descriptions and cache them in std::map
     *
     * @param forceRefresh true if you want to reinitialize mappings
     */
    void fetchCynaraPolicyDescriptions(bool forceRefresh = false);

    /**
     * Calculate actual Cynara policy based on appilcation data & previous policy
     *
     * @param label application identifier
     * @param user user for which we are calculating the policy
     * @param privileges new privielges for which policy is being calulated
     * @param bucket bucket to which the policy will be set
     * @param policyToSet policy effect to be set
     * @param policies current policy (input/output parameter)
     */
    void calculatePolicies(const std::string &label, const std::string &user,
                           const std::vector<std::string> &privileges,
                           const std::string &bucket, int policyToSet,
                           std::vector<CynaraAdminPolicy> &policies);

    static TypeToDescriptionMap s_typeToDescription;
    static DescriptionToTypeMap s_descriptionToType;

    struct cynara_admin *m_cynaraAdmin;
    bool m_policyDescriptionsInitialized;
};

class Cynara
{
public:
    Cynara();
    ~Cynara();

    /**
     * Ask Cynara for permission.
     *
     * @param label application Smack label
     * @param privilege privilege identifier
     * @param user user identifier (uid)
     * @param session session identifier
     * @return true if access is permitted, false if denied
     */
    bool check(const std::string &label, const std::string &privilege,
        const std::string &user, const std::string &session);

private:
    static const int CACHE_SIZE = 100;

    void statusCallback(int oldFd, int newFd, cynara_async_status status);

    static void statusCallback(int oldFd, int newFd,
        cynara_async_status status, void *ptr);

    static void responseCallback(cynara_check_id checkId,
        cynara_async_call_cause cause, int response, void *ptr);

    void run();

    void threadNotifyPut();
    void threadNotifyGet();

    cynara_async *m_cynara;
    std::mutex m_mutex;
    std::thread m_thread;

    const int m_eventFd;
    std::atomic<int> m_cynaraFd;
    std::atomic<short> m_cynaraFdEvents;
    std::atomic<bool> m_terminate;
};

} // namespace SecurityManager
