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
 * @file        cookie.cpp
 * @author      Pawel Polawski (p.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contain implementation of CookieService
 */

#include <memory>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <protocols.h>
#include <security-server.h>
#include <security-server-common.h>
#include <cookie.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/smack.h>

//interfaces ID
const int INTERFACE_GET = 0;
const int INTERFACE_CHECK = 1;

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector CookieService::GetServiceDescription() {
    ServiceDescription sd1 = {
        "security-server::api-cookie-get",
        INTERFACE_GET,
        SERVICE_SOCKET_COOKIE_GET
    };
    ServiceDescription sd2 = {
        "security-server::api-cookie-check",
        INTERFACE_CHECK,
        SERVICE_SOCKET_COOKIE_CHECK
    };
    ServiceDescriptionVector v;
    v.push_back(sd1);
    v.push_back(sd2);
    return v;
}

void CookieService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
    auto &info = m_socketInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void CookieService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void CookieService::read(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_socketInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(readOne(event.connectionID, info.buffer, info.interfaceID));
}

void CookieService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_socketInfoMap.erase(event.connectionID.counter);
}

void CookieService::error(const ErrorEvent &event) {
    LogDebug("ErrorEvent. ConnectionID: " << event.connectionID.sock);
    m_serviceManager->Close(event.connectionID);
}

bool CookieService::readOne(const ConnectionID &conn, SocketBuffer &buffer, int interfaceID)
{
    LogDebug("Iteration begin");
    SocketBuffer send, recv;
    int msgType;

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    //receive data from buffer and check MSG_ID
    Try {
        Deserialization::Deserialize(buffer, msgType);  //receive MSG_ID
    } Catch (SocketBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    bool retval = false;

    //use received data
    if (interfaceID == INTERFACE_GET) {
        switch(msgType) {
        case CookieGet::COOKIE:
            LogDebug("Entering get-cookie server side handler");
            retval = cookieRequest(send, conn.sock);
            break;

        default:
            LogDebug("Error, unknown function called by client");
            retval = false;
            break;
        };
    } else if (interfaceID == INTERFACE_CHECK) {
        switch(msgType) {
        case CookieGet::PID:
            LogDebug("Entering pid-by-cookie server side handler");
            retval = pidByCookieRequest(buffer, send);
            break;

        case CookieGet::SMACKLABEL:
            LogDebug("Entering smacklabel-by-cookie server side handler");
            retval = smackLabelByCookieRequest(buffer, send);
            break;

        case CookieGet::PRIVILEGE_GID:
            LogDebug("Entering check-privilege-by-cookie-gid server side handler");
            retval = privilegeByCookieGidRequest(buffer, send);
            break;

        case CookieGet::PRIVILEGE:
            LogDebug("Entering check-privilege-by-cookie side handler");
            retval = privilegeByCookieRequest(buffer, send);
            break;

        default:
            LogDebug("Error, unknown function called by client");
            retval = false;
            break;
        };
    } else {
        LogDebug("Error, wrong interface");
        retval = false;
    }

    if (retval == false) {  //something goes wrong with communication
        LogDebug("Closing socket because of error");
        m_serviceManager->Close(conn);
        return retval;
    } else {
        //send response
        m_serviceManager->Write(conn, send.Pop());
        return retval;
    }
}

bool CookieService::cookieRequest(SocketBuffer &send, int socket)
{
    struct ucred cr;
    unsigned len = sizeof(cr);

    if (0 != getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &cr, &len))
        return false;

    const Cookie *generatedCookie = m_cookieJar.GenerateCookie(cr.pid);
    if (generatedCookie != NULL) {
        //cookie created correct
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        Serialization::Serialize(send, generatedCookie->cookieId);
    } else {
        //unable to create cookie
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_UNKNOWN);
    }

    return true;
}

bool CookieService::pidByCookieRequest(SocketBuffer &buffer, SocketBuffer &send)
{
    std::vector<char> cookieKey;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
    } Catch (SocketBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL) {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        Serialization::Serialize(send, searchResult->pid);
    } else {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE);
    }

    return true;
}

bool CookieService::smackLabelByCookieRequest(SocketBuffer &buffer, SocketBuffer &send)
{
    std::vector<char> cookieKey;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
    } Catch (SocketBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL) {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        Serialization::Serialize(send, searchResult->smackLabel);
    } else {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE);
    }

    return true;
}

bool CookieService::privilegeByCookieGidRequest(SocketBuffer &buffer, SocketBuffer &send)
{
    std::vector<char> cookieKey;
    int gid;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
        Deserialization::Deserialize(buffer, gid);
    } Catch (SocketBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL)
        //search for specified GID on permissions list
        for (size_t i = 0; i < searchResult->permissions.size(); i++)
            if (searchResult->permissions[i] == gid) {
                Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
                return true;
            }

    Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_ACCESS_DENIED);

    return true;
}

bool CookieService::privilegeByCookieRequest(SocketBuffer &buffer, SocketBuffer &send)
{
    std::vector<char> cookieKey;
    std::string subject;
    std::string object;
    std::string access;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
        Deserialization::Deserialize(buffer, object);
        Deserialization::Deserialize(buffer, access);
    } Catch (SocketBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL) {
        subject = searchResult->smackLabel;

        if (smack_have_access(subject.c_str(), object.c_str(), access.c_str()) == 1)
            Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        else
            Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_ACCESS_DENIED);
    } else {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE);
    }

    return true;
}

} // namespace SecurityServer

