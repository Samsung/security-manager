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
 * @file        open-for.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @version     1.0
 * @brief       Implementation of open-for service
 */

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <protocols.h>
#include <open-for.h>
#include <unistd.h>
#include <algorithm>

#include <security-server.h>
#include <security-server-util.h>
#include <security-server-comm.h>

namespace {
// Service may open more than one socket.
// These ID's will be assigned to sockets
// and will be used only by service.
// When new connection arrives, AcceptEvent
// will be generated with proper ID to inform
// service about input socket.
//
// Please note: SocketManaged does not use it and
// does not check it in any way.
//
// If your service require only one socket
// (uses only one socket labeled with smack)
// you may ignore this ID (just pass 0)
const int SERVICE_SOCKET_ID = 0;

} // namespace anonymous

namespace SecurityServer {

OpenForService::OpenForConnInfo::~OpenForConnInfo() {
    std::for_each(descriptorsVector.begin(),descriptorsVector.end(), ::close);
}

GenericSocketService::ServiceDescriptionVector OpenForService::GetServiceDescription() {
    return ServiceDescriptionVector
        {{SERVICE_SOCKET_OPEN_FOR, "security-server::api-open-for", SERVICE_SOCKET_ID, true}};
}

void OpenForService::accept(const AcceptEvent &event)
{
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
}

void OpenForService::write(const WriteEvent &event)
{
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void OpenForService::process(const ReadEvent &event)
{
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, info.buffer, info.descriptorsVector));
}

void OpenForService::close(const CloseEvent &event)
{
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    auto &descVector = m_connectionInfoMap[event.connectionID.counter].descriptorsVector;

    for (auto iter = descVector.begin(); iter != descVector.end(); ++iter)
        TEMP_FAILURE_RETRY(::close(*iter));

    m_connectionInfoMap.erase(event.connectionID.counter);
}

bool OpenForService::processOne(const ConnectionID &conn, MessageBuffer &buffer, std::vector<int> &descVector)
{
    LogDebug("Iteration begin");

    std::string filename;
    MessageBuffer sendBuffer;

    int retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
    int fd = -1;

    if (!buffer.Ready())
        return false;

    Try {
        Deserialization::Deserialize(buffer, filename);
    } Catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    retCode = m_sharedFile.getFD(filename, conn.sock, fd);
    if (fd != -1)
        descVector.push_back(fd);
    SendMsgData sendMsgData(retCode, fd);

    m_serviceManager->Write(conn, sendMsgData);

    return true;
}

} // namespace SecurityServer
