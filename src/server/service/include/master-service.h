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
 * @file        master-service.h
 * @author      Lukasz Kostyra <l.kostyra@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Implementation of security-manager master service
 */

#ifndef _SECURITY_MANAGER_MASTER_SERVICE_
#define _SECURITY_MANAGER_MASTER_SERVICE_

#include "base-service.h"

namespace SecurityManager {

class MasterServiceException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, InvalidAction)
};

class MasterService :
    public SecurityManager::BaseService
{
public:
    MasterService();
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
     * Process Cynara policy update during app installation/uninstallation
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  zoneId ID of zone which requested the call
     */
    void processCynaraUpdatePolicy(MessageBuffer &buffer, MessageBuffer &send,
                                   const std::string &zoneId);

    /**
     * Process Cynara user initialization
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processCynaraUserInit(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process Cynara user removal
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processCynaraUserRemove(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process policy update
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processPolicyUpdate(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process configured policy acquisition
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    void processGetConfiguredPolicy(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process policy acquisition from Master
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     */
    // FIXME this function is not yet implemented.
    void processGetPolicy(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process policy descriptions list acquisition
     *
     * @param  send   Raw data buffer to be sent
     */
    void processPolicyGetDesc(MessageBuffer &send);

    /**
     * Process SMACK rules installation for package. Map rules using Smack Namespaces.
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  zoneId ID of zone which requested the call
     */
    void processSmackInstallRules(MessageBuffer &buffer, MessageBuffer &send,
                                  const std::string &zoneId);

    /**
     * Process SMACK rules uninstallation
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @param  zoneId ID of zone which requested the call
     */
    void processSmackUninstallRules(MessageBuffer &buffer, MessageBuffer &send,
                                    const std::string &zoneId);
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_MASTER_SERVICE_
