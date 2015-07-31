/*
 *  Copyright (c) 2014-2015 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef _SECURITY_MANAGER_SERVICE_IMPL_
#define _SECURITY_MANAGER_SERVICE_IMPL_

#include <unistd.h>
#include <sys/types.h>

#include <unordered_set>

#include "security-manager.h"

namespace SecurityManager {
namespace ServiceImpl {

/**
 * Retrieves ID (UID and PID) of peer connected to socket
 *
 * @param[in]  Socket file descriptor
 * @param[out] UID of connected peer. Function does not modify the variable if ID retrieval fails.
 * @param[out] PID of connected peer. Function does not modify the variable if ID retrieval fails.
 *
 * @return True if peer ID was successfully retrieved, false otherwise.
 */
bool getPeerID(int sock, uid_t &uid, pid_t &pid);

/**
 * Process application installation request.
 *
 * @param[in] req installation request
 * @param[in] uid id of the requesting user
 * @param[in] isSlave Indicates if function should be called under slave mode
 *
 * @return API return code, as defined in protocols.h
 */
int appInstall(const app_inst_req &req, uid_t uid, bool isSlave);

/**
 * Process application uninstallation request.
 *
 * @param[in] req uninstallation request
 * @param[in] uid id of the requesting user
 * @param[in] isSlave Indicates if function should be called under slave mode
 *
 * @return API return code, as defined in protocols.h
 */
int appUninstall(const std::string &appId, uid_t uid, bool isSlave);

/**
 * Process package id query.
 * Retrieves the package id associated with given application id.
 *
 * @param[in] appId application identifier
 * @param[out] pkgId returned package identifier
 *
 * @return API return code, as defined in protocols.h
 */
int getPkgId(const std::string &appId, std::string &pkgId);

/**
 * Process query for supplementary groups allowed for the application.
 * For given appId and uid, calculate allowed privileges that give
 * direct access to file system resources. For each permission Cynara will be
 * queried.
 * Returns set of group ids that are permitted.
 *
 * @param[in]  appId application identifier
 * @param[in]  uid id of the requesting user
 * @param[in]  pid id of the requesting process (to construct Cynara session id)
 * @param[in]  isSlave Indicates if function should be called under slave mode
 * @param[out] gids returned set of allowed group ids
 *
 * @return API return code, as defined in protocols.h
 */
int getAppGroups(const std::string &appId, uid_t uid, pid_t pid, bool isSlave,
        std::unordered_set<gid_t> &gids);

/**
 * Process user adding request.
 *
 * @param[in] uidAdded uid of newly created user
 * @param[in] userType type of newly created user
 * @param[in] uid uid of requesting user
 * @param[in] isSlave Indicates if function should be called under slave mode
 *
 * @return API return code, as defined in protocols.h
 */
int userAdd(uid_t uidAdded, int userType, uid_t uid, bool isSlave);

/**
 * Process user deletion request.
 *
 * @param[in] uidDeleted uid of removed user
 * @param[in] uid uid of requesting user
 * @param[in] isSlave Indicates if function should be called under slave mode
 *
 * @return API return code, as defined in protocols.h
 */
int userDelete(uid_t uidDeleted, uid_t uid, bool isSlave);

/**
 * Update policy in Cynara - proper privilege: http://tizen.org/privilege/systemsettings.admin
 * is needed for this to succeed
 *
 * @param[in] policyEntries vector of policy chunks with instructions
 * @param[in] uid identifier of requesting user
 * @param[in] pid PID of requesting process
 * @param[in] smackLabel smack label of requesting app
 *
 * @return API return code, as defined in protocols.h
 */

int policyUpdate(const std::vector<policy_entry> &policyEntries, uid_t uid, pid_t pid, const std::string &smackLabel);
/**
 * Fetch all configured privileges from user configurable bucket.
 * Depending on forAdmin value: personal user policies or admin enforced
 * policies are returned.
 *
 * @param[in] forAdmin determines if user is asking as ADMIN or not
 * @param[in] filter filter for limiting the query
 * @param[in] uid identifier of queried user
 * @param[in] pid PID of requesting process
 * @param[out] policyEntries vector of policy entries with result
 *
 * @return API return code, as defined in protocols.h
 */
int getConfiguredPolicy(bool forAdmin, const policy_entry &filter, uid_t uid, pid_t pid, const std::string &smackLabel, std::vector<policy_entry> &policyEntries);

/**
 * Fetch all privileges for all apps installed for specific user.
 *
 * @param[in] forAdmin determines if user is asking as ADMIN or not
 * @param[in] filter filter for limiting the query
 * @param[in] uid identifier of queried user
 * @param[in] pid PID of requesting process
 * @param[out] policyEntries vector of policy entries with result
 *
 * @return API return code, as defined in protocols.h
 */
int getPolicy(const policy_entry &filter, uid_t uid, pid_t pid, const std::string &smackLabel, std::vector<policy_entry> &policyEntries);

/**
 * Process getting policy descriptions list.
 *
 * @param[in] descriptions empty vector for descriptions strings
 *
 * @return API return code, as defined in protocols.h
 */
int policyGetDesc(std::vector<std::string> &descriptions);

/**
 * Process getting privileges mappings from one version to another.
 *
 * @param[in] version_from version to be mapped from
 * @param[in] version_to version to be mapped to
 * @param[in] privileges vector of privileges to be mapped
 * @param[out] mappings mappings of given privileges
 */
int getPrivilegesMappings(const std::string &version_from,
                          const std::string &version_to,
                          const std::vector<std::string> &privileges,
                          std::vector<std::string> &mappings);

/**
 * Process getting resources group list.
 *
 * @param[out] groups empty vector for group strings
 *
 * @return API return code, as defined in protocols.h
 */
int policyGetGroups(std::vector<std::string> &groups);

} /* namespace ServiceImpl */
} /* namespace SecurityManager */

#endif /* _SECURITY_MANAGER_SERVICE_IMPL_ */
