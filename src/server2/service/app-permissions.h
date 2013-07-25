/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @author      Pawel Polawski (pawel.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contain header for implementation of security_server_app_enable_permissions
 *              and SS_app_disable_permissions on server side
 */

#ifndef _SECURITY_SERVER_APP_PERMISSIONS_
#define _SECURITY_SERVER_APP_PERMISSIONS__

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <dpl/serialization.h>
#include <socket-buffer.h>
#include <security-server-common.h>

namespace SecurityServer {

class AppPermissionsService  :
    public SecurityServer::GenericSocketService
  , public SecurityServer::ServiceThread<AppPermissionsService>
{
public:
    typedef std::map<int, SocketBuffer> SocketBufferMap;

    ServiceDescriptionVector GetServiceDescription();

    DECLARE_THREAD_EVENT(AcceptEvent, accept)
    DECLARE_THREAD_EVENT(WriteEvent, write)
    DECLARE_THREAD_EVENT(ReadEvent, read)
    DECLARE_THREAD_EVENT(CloseEvent, close)
    DECLARE_THREAD_EVENT(ErrorEvent, error)

    void accept(const AcceptEvent &event);
    void write(const WriteEvent &event);
    void read(const ReadEvent &event);
    void close(const CloseEvent &event);
    void error(const ErrorEvent &event);

private:
    bool readOne(const ConnectionID &conn, SocketBuffer &buffer);

    SocketBufferMap m_socketBufferMap;
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_APP_ENABLE_PERMISSIONS_
