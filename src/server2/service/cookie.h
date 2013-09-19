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
 * @file        cookie.h
 * @author      Pawel Polawski (p.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contain header for implementation of cookie get API
 */

#ifndef _SECURITY_SERVER_COOKIE_GET_
#define _SECURITY_SERVER_COOKIE_GET_

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <dpl/serialization.h>
#include <message-buffer.h>
#include <security-server-common.h>
#include <cookie-jar.h>

namespace SecurityServer {

class CookieService  :
    public SecurityServer::GenericSocketService
  , public SecurityServer::ServiceThread<CookieService>
{
public:
    struct SocketInfo
    {
        int interfaceID;
        MessageBuffer buffer;
    };

    typedef std::map<int, SocketInfo> SocketInfoMap;

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
    bool readOne(const ConnectionID &conn, MessageBuffer &buffer, int interfaceID);

    bool cookieRequest(MessageBuffer &send, int socket);

    bool pidByCookieRequest(MessageBuffer &buffer, MessageBuffer &send);
    bool smackLabelByCookieRequest(MessageBuffer &buffer, MessageBuffer &send);
    bool privilegeByCookieGidRequest(MessageBuffer &buffer, MessageBuffer &send);
    bool privilegeByCookieRequest(MessageBuffer &buffer, MessageBuffer &send);

    bool uidByCookieRequest(MessageBuffer &buffer, MessageBuffer &send);
    bool gidByCookieRequest(MessageBuffer &buffer, MessageBuffer &send);

    CookieJar m_cookieJar;

    SocketInfoMap m_socketInfoMap;
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_APP_ENABLE_PERMISSIONS_
