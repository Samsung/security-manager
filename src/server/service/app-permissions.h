/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bartlomiej Grzelewski <b.grzelewski@samsung.com>
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
 * @file        app-permissions.h
 * @author      Pawel Polawski (p.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contains header for implementation of
 *              security_server_app_has_permissions on server side
 */

#ifndef _SECURITY_SERVER_APP_PERMISSIONS_
#define _SECURITY_SERVER_APP_PERMISSIONS_

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <dpl/serialization.h>
#include <message-buffer.h>
#include <connection-info.h>

namespace SecurityServer {

class AppPermissionsService  :
    public SecurityServer::GenericSocketService
  , public SecurityServer::ServiceThread<AppPermissionsService>
{
public:
    ServiceDescriptionVector GetServiceDescription();

    DECLARE_THREAD_EVENT(AcceptEvent, accept)
    DECLARE_THREAD_EVENT(WriteEvent, write)
    DECLARE_THREAD_EVENT(ReadEvent, process)
    DECLARE_THREAD_EVENT(CloseEvent, close)

    void accept(const AcceptEvent &event);
    void write(const WriteEvent &event);
    void process(const ReadEvent &event);
    void close(const CloseEvent &event);

private:
    bool processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID);

    bool processCheckAppPrivilege(const ConnectionID &conn, MessageBuffer &buffer);

    ConnectionInfoMap m_connectionInfoMap;
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_APP_ENABLE_PERMISSIONS_
