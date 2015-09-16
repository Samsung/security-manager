/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        master-req.h
 * @author      Lukasz Kostyra <l.kostyra@samsung.com>
 * @brief       Master request calls declaration
 */

#ifndef _SECURITY_MANAGER_MASTER_REQ_
#define _SECURITY_MANAGER_MASTER_REQ_

#include <string>
#include <vector>

#include "protocols.h"


namespace SecurityManager {
namespace MasterReq {

/**
 * Forwards Cynara Policy Update request to Master Service.
 *
 * @param[in]  appID            Application ID
 * @param[in]  uidstr           String containing user identifier
 * @param[in]  privileges       Currently enabled privileges for the application
 *
 * @see CynaraAdmin::UpdateAppPolicy
 */
int CynaraPolicyUpdate(const std::string &appId, const std::string &uidstr,
                       const std::vector<std::string> &privileges);

/**
 * Forwards Cynara user initialization to Master service.
 *
 * @param[in]  uidAdded New user UID
 * @param[in]  userType Type of user, enumerated in security-manager.h
 * @return API return code, as defined in protocols.h
 *
 * @see CynaraAdmin::UserInit
 */
int CynaraUserInit(const uid_t uidAdded, int userType);

/**
 * Forwards Cynara user removal to Master service.
 *
 * @param[in] uidDeleted Removed user UID
 * @return API return code, as defined in protocols.h
 *
 * @see CynaraAdmin::UserRemove
 */
int CynaraUserRemove(const uid_t uidDeleted);

/**
 * Forwards SMACK rule installation to Master service.
 *
 * @param[in]  appId       ID of application being removed
 * @param[in]  pkgId       ID of package being removed
 * @param[in]  pkgContents A list of all applications in the package
 * @return API return code, as defined in protocols.h
 *
 * @see SmackRules::installApplicationRules
 */
int SmackInstallRules(const std::string &appId, const std::string &pkgId,
                      const std::vector<std::string> &pkgContents);

/**
 * Forwards SMACK rule removal to Master service.
 *
 * @param[in]  appId       ID of application being removed
 * @param[in]  pkgId       ID of package being removed
 * @param[in]  pkgContents A list of all applications in the package
 * @param[in]  removePkg   Flag stating if entire package should be removed
 * @return API return code, as defined in protocols.h
 *
 * @see SmackRules::uninstallPackageRules, SmackRules::uninstallApplicationRules
 */
int SmackUninstallRules(const std::string &appId, const std::string &pkgId,
                        const std::vector<std::string> &pkgContents, const bool removePkg);

/**
 * Forwards policyUpdate API to Master. Arguments are the same as policyUpdate.
 *
 * @return API return code, as defined in protocols.h
 *
 * @see ServiceImpl::policyUpdate
 */
int PolicyUpdate(const std::vector<policy_entry> &policyEntries, uid_t uid, pid_t pid,
                 const std::string &smackLabel);

/**
 * Forwards getConfiguredPolicy API to Master. Arguments are the same as getConfiguredPolicy.
 *
 * @return API return code, as defined in protocols.h
 *
 * @see ServiceImpl::getConfiguredPolicy
 */
int GetConfiguredPolicy(bool forAdmin, const policy_entry &filter, uid_t uid, pid_t pid,
                        const std::string &smackLabel, std::vector<policy_entry> &policyEntries);

/**
 * Forwards getPolicy API to Master. Arguments are the same as getPolicy.
 *
 * @return API return code, as defined in protocols.h
 *
 * @see ServiceImpl::getPolicy
 */
int GetPolicy(const policy_entry &filter, uid_t uid, pid_t pid, const std::string &smackLabel,
              std::vector<policy_entry> &policyEntries);

/**
 * Forwards policyGetDesc API to Master. Arguments are the same as policyGetDesc.
 *
 * @return API return code, as defined in protocols.h
 *
 * @see ServiceImpl::policyGetDesc
 */
int PolicyGetDesc(std::vector<std::string> &descriptions);

} // namespace MasterReq
} // namespace SecurityManager

#endif // _SECURITY_MANAGER_MASTER_REQ_
