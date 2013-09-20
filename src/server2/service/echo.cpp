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
 * @file        server-main2.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of sample service.
 */

#include <dpl/log/log.h>

#include <protocols.h>
#include <echo.h>

namespace {
// Service may open more than one socket.
// This ID's will be assigned to sockets.
// This ID's will be used only by service.
// When new connection arrives, AcceptEvent
// will be generated with proper ID to inform
// service about input socket.
//
// Please note: SocketManaged does not use it and
// does not check it in any way.
//
// If your service require only one socket
// (uses only one socet labeled with smack)
// you may ignore this ID (just pass 0)
const int SERVICE_SOCKET_ID = 0;
} // namespace anonymous

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector EchoService::GetServiceDescription() {
    ServiceDescription sd = {
        "security-server::api-echo",
        SERVICE_SOCKET_ID,
        SERVICE_SOCKET_ECHO
    };
    ServiceDescriptionVector v;
    v.push_back(sd);
    return v;
}

void EchoService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID: " << event.connectionID.sock
        << " ServiceID: " << event.interfaceID);
}

void EchoService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void EchoService::read(const ReadEvent &event) {
    LogDebug("ReadEvent. ConnectionID: " << event.connectionID.sock <<
      " Buffer size: " << event.rawBuffer.size());
    m_serviceManager->Write(event.connectionID, event.rawBuffer);
    LogDebug("Write completed");
}

void EchoService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
}

} // namespace SecurityServer

