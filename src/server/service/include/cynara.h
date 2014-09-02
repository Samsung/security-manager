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
 * @file        cynara.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Wrapper class for Cynara interface
 */

#ifndef _SECURITY_MANAGER_CYNARA_
#define _SECURITY_MANAGER_CYNARA_

#include <cynara-client.h>
#include <cynara-admin.h>
#include <dpl/exception.h>
#include <string>

namespace SecurityManager {

class CynaraException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, OutOfMemory)
    DECLARE_EXCEPTION_TYPE(Base, InvalidParam)
    DECLARE_EXCEPTION_TYPE(Base, ServiceNotAvailable)
    DECLARE_EXCEPTION_TYPE(Base, UnknownError)
};

struct CynaraAdminPolicy : cynara_admin_policy
{
    enum class Operation {
        Deny = CYNARA_ADMIN_DENY,
        Allow = CYNARA_ADMIN_ALLOW,
        Delete = CYNARA_ADMIN_DELETE,
        Bucket = CYNARA_ADMIN_BUCKET,
    };

    CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, Operation operation,
        const std::string &bucket = std::string(CYNARA_ADMIN_DEFAULT_BUCKET));

    CynaraAdminPolicy(const std::string &client, const std::string &user,
        const std::string &privilege, const std::string &goToBucket,
        const std::string &bucket = std::string(CYNARA_ADMIN_DEFAULT_BUCKET));

    /* Don't provide copy constructor, it would cause pointer trouble. */
    CynaraAdminPolicy(const CynaraAdminPolicy &that) = delete;

    /* Move constructor is the way to go. */
    CynaraAdminPolicy(CynaraAdminPolicy &&that);

    ~CynaraAdminPolicy();
};

class CynaraAdmin
{
public:
    CynaraAdmin();
    virtual ~CynaraAdmin();

    /**
     * Update Cynara policies.
     * Caller must have permission to access Cynara administrative socket.
     *
     * @param policies vector of CynaraAdminPolicy objects to send to Cynara
     */
    void SetPolicies(const std::vector<CynaraAdminPolicy> &policies);

    /**
     * Update Cynara policies for the package and the user, using two vectors
     * of privileges: privileges set before (and already enabled in Cynara)
     * and new privileges, to be set in Cynara.
     * Difference will be calculated, removing old unneeded privileges and
     * adding new, previously not enabled privileges.
     * Caller must have permission to access Cynara administrative socket.
     *
     * @param label application Smack label
     * @param user user identifier
     * @param oldPrivileges previously enabled privileges for the package.
     *        Must be sorted and without duplicates.
     * @param newPrivileges currently enabled privileges for the package.
     *        Must be sorted and without duplicates.
     *
     * TODO: drop oldPrivileges argument and get them directly from Cynara.
     * Appropriate Cynara interface is needed first.
     */
    static void UpdatePackagePolicy(const std::string &label, const std::string &user,
        const std::vector<std::string> &oldPrivileges,
        const std::vector<std::string> &newPrivileges);

private:
    struct cynara_admin *m_CynaraAdmin;
};

class Cynara
{
public:
    Cynara();
    virtual ~Cynara();

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
    struct cynara *m_Cynara;
};


} // namespace SecurityManager

#endif // _SECURITY_MANAGER_CYNARA_
