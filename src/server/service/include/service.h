/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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

#ifndef _SECURITY_MANAGER_SERVICE_
#define _SECURITY_MANAGER_SERVICE_

#include "base-service.h"

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
     * @param  uid    User's identifier for whom application will be installed
     */
    void processAppInstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid);

    /**
     * Process application uninstallation
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  uid    User's identifier for whom application will be uninstalled
     */
    void processAppUninstall(MessageBuffer &buffer, MessageBuffer &send, uid_t uid);

    /**
     * Process getting package id from app id
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processGetPkgId(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process getting permitted group ids for app id
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  uid    User's identifier for whom application will be launched
     * @param  pid    Process id in which application will be launched
     */
    void processGetAppGroups(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid);

    void processUserAdd(MessageBuffer &buffer, MessageBuffer &send, uid_t uid);

    void processUserDelete(MessageBuffer &buffer, MessageBuffer &send, uid_t uid);

    /**
     * Process policy update request
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  uid    Identifier of the user who sent the request
     * @param  pid    PID of the process which sent the request
     * @param  smackLabel smack label of requesting app
     */
    void processPolicyUpdate(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid, const std::string &smackLabel);

    /**
     * List all privileges for specific user, placed in Cynara's PRIVACY_MANAGER
     * or ADMIN's bucket - choice based on forAdmin parameter
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  uid    Identifier of the user who sent the request
     * @param  pid    PID of the process which sent the request
     * @param  smackLabel smack label of requesting app
     * @param  forAdmin determines internal type of request
     */
    void processGetConfiguredPolicy(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid, const std::string &smackLabel, bool forAdmin);

    /**
     * Get whole policy for specific user. Whole policy is a list of all apps,
     * and their permissions (based on what they've stated in their manifests).
     * If uid is unprivileged, then only privileges for the caller uid will be
     * listed. If uid is privileged, then apps for all the users will be listed.
     *
     * @param  buffer Raw received data buffer
     * @param  send     Raw data buffer to be sent
     * @param  uid      Identifier of the user who sent the request
     * @param  pid      PID of the process which sent the request
     * @param  smackLabel smack label of requesting app
     */
    void processGetPolicy(MessageBuffer &buffer, MessageBuffer &send, uid_t uid, pid_t pid, const std::string &smackLabel);

};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_SERVICE_
