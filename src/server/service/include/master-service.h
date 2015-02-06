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
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_MASTER_SERVICE_
