/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        service.h
 * @author      Michal Witanowski <m.witanowski@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager service
 */

#pragma once

#include "base-service.h"
#include "credentials.h"
#include "service_impl.h"

namespace SecurityManager {

class ServiceException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, InvalidAction)
};

class Service :
    public SecurityManager::BaseService
{
public:
    Service();
    ServiceDescriptionVector GetServiceDescription();

private:
    ServiceImpl serviceImpl;

    /**
     * Handle request from a client
     *
     * @param  conn        Socket connection information
     * @param  buffer      Raw received data buffer
     * @param  interfaceID identifier used to distinguish source socket
     * @return             true on success
     */
    bool processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID);

    /**
     * Process application installation
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processAppInstall(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds);

    /**
     * Process application uninstallation
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processAppUninstall(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds);

    /**
     * Process getting package identifier from an app identifier
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processGetPkgName(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process getting permitted group ids for app id
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processGetAppGroups(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds);

    void processUserAdd(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds);

    void processUserDelete(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds);

    /**
     * Process policy update request
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processPolicyUpdate(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds);

    /**
     * List all privileges for specific user, placed in Cynara's PRIVACY_MANAGER
     * or ADMIN's bucket - choice based on forAdmin parameter
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     * @param  forAdmin determines internal type of request
     */
    void processGetConfiguredPolicy(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds, bool forAdmin);

    /**
     * Get whole policy for specific user. Whole policy is a list of all apps,
     * and their permissions (based on what they've stated in their manifests).
     *
     * If calling user is unprivileged, then only privileges for the caller uid
     * will be listed. If caller is privileged, then apps for all the users will
     * be listed.
     *
     * @param  buffer Raw received data buffer
     * @param  send     Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processGetPolicy(MessageBuffer &buffer, MessageBuffer &send, const Credentials &creds);

    /**
     * Process getting policies descriptions as strings from Cynara
     *
     * @param  recv   Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processPolicyGetDesc(MessageBuffer &send);

    /**
     * Process getting groups bound with privileges
     *
     * @param  send   Raw data buffer to be sent
     */
    void processGroupsGet(MessageBuffer &send);

    /**
     * Process getting groups bound with privileges for given uid
     *
     * @param  send   Raw data buffer to be sent
     */
    void processGroupsForUid(MessageBuffer &recv, MessageBuffer &send);

    /**
     * Process checking application's privilege access based on app_id
     *
     * @param  recv   Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processAppHasPrivilege(MessageBuffer &recv, MessageBuffer &send);

    /**
     * Process applying private path sharing between applications.
     *
     * @param  recv   Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processApplyPrivateSharing(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds);

    /**
     * Process drop private path sharing between applications.
     *
     * @param  recv   Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processDropPrivateSharing(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds);

    /**
     * Process package paths registration request
     *
     * @param  recv   Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processPathsRegister(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds);

    /**
     * Generate process label request
     *
     * @param  recv   Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processLabelForProcess(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process shared memory access request
     *
     * @param  recv   Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  creds  credentials of the requesting process
     */
    void processShmAppName(MessageBuffer &recv, MessageBuffer &send, const Credentials &creds);
};

} // namespace SecurityManager
