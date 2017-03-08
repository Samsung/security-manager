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
 * @file        service_impl.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of the service methods
 */

#pragma once

#include <unistd.h>
#include <sys/types.h>

#include <vector>

#include "credentials.h"
#include "cynara.h"
#include "security-manager.h"
#include "smack-rules.h"
#include "protocols.h"
#include "privilege_db.h"

namespace SecurityManager {

class ServiceImpl {
public:
    ServiceImpl();
    virtual ~ServiceImpl();

    /**
    * Process application installation request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] req installation request
    *
    * @return API return code, as defined in protocols.h
    */
    int appInstall(const Credentials &creds, app_inst_req &&req);

    /**
    * Process application uninstallation request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] req uninstallation request
    *
    * @return API return code, as defined in protocols.h
    */
    int appUninstall(const Credentials &creds, app_inst_req &&req);

    /**
    * Process package id query.
    * Retrieves the package id associated with given application id.
    *
    * @param[in] appName application identifier
    * @param[out] pkgName returned package identifier
    *
    * @return API return code, as defined in protocols.h
    */
    int getPkgName(const std::string &appName, std::string &pkgName);

    /**
    * Process query for supplementary groups allowed for the application.
    * For given \ref appName and \ref uid, calculate allowed privileges that give
    * direct access to file system resources. For each permission Cynara will be
    * queried.
    * Returns set of group ids that are permitted.
    *
    * @param[in]  creds credentials of the requesting process
    * @param[in]  appName application identifier
    * @param[out] groups returned vector of allowed groups
    *
    * @return API return code, as defined in protocols.h
    */
    int getAppGroups(const Credentials &creds, const std::string &appName,
        std::vector<std::string> &groups);

    /**
    * Process user adding request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] uidAdded uid of newly created user
    * @param[in] userType type of newly created user
    *
    * @return API return code, as defined in protocols.h
    */
    int userAdd(const Credentials &creds, uid_t uidAdded, int userType);

    /**
    * Process user deletion request.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] uidDeleted uid of removed user
    *
    * @return API return code, as defined in protocols.h
    */
    int userDelete(const Credentials &creds, uid_t uidDeleted);

    /**
    * Update policy in Cynara - proper privilege: http://tizen.org/privilege/internal/usermanagement
    * is needed for this to succeed
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] policyEntries vector of policy chunks with instructions
    *
    * @return API return code, as defined in protocols.h
    */
    int policyUpdate(const Credentials &creds, const std::vector<policy_entry> &policyEntries);

    /**
    * Fetch all configured privileges from user configurable bucket.
    * Depending on forAdmin value: personal user policies or admin enforced
    * policies are returned.
    *
    * @param[in] forAdmin determines if user is asking as ADMIN or not
    * @param[in] filter filter for limiting the query
    * @param[out] policyEntries vector of policy entries with result
    *
    * @return API return code, as defined in protocols.h
    */
    int getConfiguredPolicy(const Credentials &creds, bool forAdmin, const policy_entry &filter, std::vector<policy_entry> &policyEntries);

    /**
    * Fetch all privileges for all apps installed for specific user.
    *
    * @param[in] creds credentials of the requesting process
    * @param[in] filter filter for limiting the query
    * @param[out] policyEntries vector of policy entries with result
    *
    * @return API return code, as defined in protocols.h
    */
    int getPolicy(const Credentials &creds, const policy_entry &filter, std::vector<policy_entry> &policyEntries);

    /**
    * Process getting policy descriptions list.
    *
    * @param[in] descriptions empty vector for descriptions strings
    *
    * @return API return code, as defined in protocols.h
    */
    int policyGetDesc(std::vector<std::string> &descriptions);

    /**
     * Process getting resources group list.
     *
     * @param[out] groups empty vector for group strings
     *
     * @return API return code, as defined in protocols.h
     */
    int policyGetGroups(std::vector<std::string> &groups);

    /**
     * Receive groups connected with uid and add them
     * to the vector.
     *
     * @param[in] uid to return the groups for
     * @param[out] groups vector with groups
     *
     * @return API return code, as defined in protocols.h
     */
    int policyGroupsForUid(uid_t uid, std::vector<std::string> &groups);

    /**
     * Process checking application's privilege access based on app_name
     *
     * @param[in]  appName application identifier
     * @param[in]  privilege privilege name
     * @param[in]  uid user identifier
     * @param[out] result placeholder for check result
     *
     * @return API return code, as defined in protocols.h
     */
    int appHasPrivilege(std::string appName, std::string privilege, uid_t uid, bool &result);

    /**
     * Process applying private path sharing between applications.
     *
     * @param[in] creds credentials of the requesting process
     * @param[in] ownerAppName application owning paths
     * @param[in] targetAppName application which paths will be shared with
     * @param[in] paths vector of paths to be shared
     *
     * @return API return code, as defined in protocols.h
     */
    int applyPrivatePathSharing(const Credentials &creds,
                                const std::string &ownerAppName,
                                const std::string &targetAppName,
                                const std::vector<std::string> &paths);

    /**
     * Process droping private path sharing between applications.
     *
     * @param[in] creds credentials of the requesting process
     * @param[in] ownerAppName application owning paths
     * @param[in] targetAppName application which paths won't be anymore shared with
     * @param[in] paths vector of paths to be stopped being shared
     * @return API return code, as defined in protocols.h
     */
    int dropPrivatePathSharing(const Credentials &creds,
                               const std::string &ownerAppName,
                               const std::string &targetAppName,
                               const std::vector<std::string> &paths);

    /**
     * Process package paths registration.
     *
     * @param[in] creds credentials of the requesting process
     * @param[in] p_req path registration request
     *
     * @return API return code, as defined in protocols.h
     */
    int pathsRegister(const Credentials &creds, path_req p_req);

    /**
     * Generate label for process.
     *
     * @param[in] appName application identifier
     * @param[out] label generated label
     *
     * @return API return code, as defined in protocols.h
     */
    int labelForProcess(const std::string &appName, std::string &label);
    /*
     * Request for access to shared memory segment for
     * appName application.
     *
     * @param[in] creds credentials of the requesting process
     * @param[in] name shared memory identifier
     * @param[in] appName application identifier
     *
     * @return API return code, as defined in protocols.h
     */
    int shmAppName(const Credentials &creds,
                   const std::string &shmName,
                   const std::string &appName);
private:
    bool authenticate(const Credentials &creds, const std::string &privilege);

    static uid_t getGlobalUserId(void);

    static std::string realPath(const std::string &path);

    static bool isSubDir(const std::string &parent, const std::string &subdir);

    static bool containSubDir(const std::string &parent, const pkg_paths &paths);

    static bool getUserPkgDir(const uid_t &uid,
                              const std::string &pkgName,
                              app_install_type installType,
                              std::string &userPkgDir);

    static bool getSkelPkgDir(const std::string &pkgName,
                              std::string &skelPkgDir);

    static void setRequestDefaultValues(uid_t& uid, int& installationType);

    bool authCheck(const Credentials &creds,
                                        const uid_t &uid,
                                        int installationType);

    static bool pathsCheck(const pkg_paths &requestedPaths,
                           const std::vector<std::string> &allowedDirs);

    int labelPaths(const pkg_paths &paths,
                          const std::string &pkgName,
                          app_install_type installationType,
                          const uid_t &uid);

    void getPkgLabels(const std::string &pkgName, SmackRules::Labels &pkgsLabels);

    static bool isSharedRO(const pkg_paths& paths);

    int squashDropPrivateSharing(const std::string &ownerAppName,
                                 const std::string &targetAppName,
                                 const std::string &path);

    int dropOnePrivateSharing(const std::string &ownerAppName,
                              const std::string &ownerPkgName,
                              const SmackRules::Labels &ownerPkgLabels,
                              const std::string &targetAppName,
                              const std::string &targetAppLabel,
                              const std::string &path);

    void updatePermissibleSet(uid_t uid, int type);

    std::string getAppProcessLabel(const std::string &appName, const std::string &pkgName);

    std::string getAppProcessLabel(const std::string &appName);

    bool sharingExists(const std::string &targetAppName, const std::string &path);

    void getPkgsProcessLabels(const std::vector<PkgInfo> &pkgsInfo, SmackRules::PkgsLabels &pkgsLabels);

    int validatePolicy(const Credentials &creds, policy_entry &policyEntry, CynaraAdminPolicy &cyap);

    Cynara m_cynara;
    PrivilegeDb m_priviligeDb;
    CynaraAdmin m_cynaraAdmin;
};

} /* namespace SecurityManager */
