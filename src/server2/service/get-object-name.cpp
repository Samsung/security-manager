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
 * @file        get-object-name.cpp
 * @author      Jan Olszak (j.olszak@samsung.com)
 * @version     1.0
 * @brief       Implementation of api-get-object-name service.
 */

#include <sys/smack.h>
#include <grp.h>
#include <unistd.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <protocols.h>
#include <get-object-name.h>
#include <security-server.h>

#include <vector>

namespace SecurityServer {

GetObjectNameService::ServiceDescriptionVector GetObjectNameService::GetServiceDescription() {
    ServiceDescription sd = {
        "*",
        0,
        SERVICE_SOCKET_GET_OBJECT_NAME
    };
    ServiceDescriptionVector v;
    v.push_back(sd);
    return v;
}

void GetObjectNameService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
}

void GetObjectNameService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}



/*
 * Searches for group NAME by given group id
 */
int GetObjectNameService::setName(const gid_t gid)
{
    int ret = 0;
    struct group *grpbuf = NULL;
    struct group grp;
    std::vector<char> buf;

    /*
     * The maximum needed size for buf can be found using sysconf(3)
     * with the argument _SC_GETGR_R_SIZE_MAX. If _SC_GETGR_R_SIZE_MAX is not
     * returned we set max_buf_size to 1024 bytes. Enough to store few groups.
     */
    long int maxBufSize = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (maxBufSize == -1)
        maxBufSize = 1024;


    /*
     * There can be some corner cases when for example user is assigned to a
     * lot of groups. In that case if buffer is to small getgrnam_r will
     * return ERANGE error. Solution could be calling getgrnam_r with bigger
     * buffer until it's big enough.
     */
    do {
        try{
            buf.resize(maxBufSize);
        }catch(std::bad_alloc&) {
            ret = SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
            LogError("Out Of Memory");
            return ret;
        }
        maxBufSize *= 2;

    } while ((ret = getgrgid_r(gid, &grp, &(buf[0]), buf.size(), &grpbuf)) == ERANGE);

    // Check for errors:
    if (ret != 0){
        ret = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
        LogError("getgrgid_r failed with error: " << strerror(errno));
        return ret;

    } else if (grpbuf == NULL) {
        ret = SECURITY_SERVER_API_ERROR_NO_SUCH_OBJECT;
        LogError("Cannot find name for group: " << gid);
        return ret;
    }

    m_name = grpbuf->gr_name;

    return ret;
}


bool GetObjectNameService::readOne(const ConnectionID &conn, MessageBuffer &buffer) {
    LogDebug("Iteration begin");
    gid_t gid;
    int retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;

    if (!buffer.Ready()) {
        return false;
    }

    // Get objects GID:
    Try {
        Deserialization::Deserialize(buffer, gid);
     } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    // Get name
    retCode = setName(gid);

    // Send the result
    MessageBuffer sendBuffer;
    Serialization::Serialize(sendBuffer, retCode);
    Serialization::Serialize(sendBuffer, m_name);
    m_serviceManager->Write(conn, sendBuffer.Pop());
    return true;
}

void GetObjectNameService::read(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &buffer = m_messageBufferMap[event.connectionID.counter];
    buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(readOne(event.connectionID, buffer));
}

void GetObjectNameService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_messageBufferMap.erase(event.connectionID.counter);
}

void GetObjectNameService::error(const ErrorEvent &event) {
    LogError("ErrorEvent. ConnectionID: " << event.connectionID.sock);
    m_serviceManager->Close(event.connectionID);
}

} // namespace SecurityServer

