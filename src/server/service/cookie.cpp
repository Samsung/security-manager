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
#include <cookie.h>
#include <smack-check.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/smack.h>

//interfaces ID
const int INTERFACE_GET = 0;
const int INTERFACE_CHECK = 1;
const int INTERFACE_CHECK_TMP = 3;

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector CookieService::GetServiceDescription() {
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_COOKIE_GET,       "security-server::api-cookie-get",   INTERFACE_GET },
        {SERVICE_SOCKET_COOKIE_CHECK,     "security-server::api-cookie-check", INTERFACE_CHECK},
        {SERVICE_SOCKET_COOKIE_CHECK_TMP, "security-server::api-cookie-check", INTERFACE_CHECK_TMP}
    };
 }

void CookieService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void CookieService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void CookieService::process(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, info.buffer, info.interfaceID));
}

void CookieService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

bool CookieService::processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID)
{
    LogDebug("Iteration begin");
    MessageBuffer send, recv;
    CookieCall msgType;
    bool removeGarbage = false;

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    //receive data from buffer and check MSG_ID
    Try {
        int msgTypeInt;
        Deserialization::Deserialize(buffer, msgTypeInt);  //receive MSG_ID
        msgType = static_cast<CookieCall>(msgTypeInt);
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    bool retval = false;

    //use received data
    if (interfaceID == INTERFACE_GET) {
        switch(msgType) {
        case CookieCall::GET_COOKIE:
            LogDebug("Entering get-cookie server side handler");
            retval = cookieRequest(send, conn.sock);
            removeGarbage = true;
            break;

        default:
            LogDebug("Error, unknown function called by client");
            retval = false;
            break;
        };
    } else if (interfaceID == INTERFACE_CHECK) {
        switch(msgType) {
        case CookieCall::CHECK_PID:
            LogDebug("Entering pid-by-cookie server side handler");
            retval = pidByCookieRequest(buffer, send);
            break;

        case CookieCall::CHECK_SMACKLABEL:
            LogDebug("Entering smacklabel-by-cookie server side handler");
            retval = smackLabelByCookieRequest(buffer, send);
            break;

        case CookieCall::CHECK_PRIVILEGE_GID:
            LogDebug("Entering check-privilege-by-cookie-gid server side handler");
            retval = privilegeByCookieGidRequest(buffer, send);
            break;

        case CookieCall::CHECK_PRIVILEGE:
            LogDebug("Entering check-privilege-by-cookie side handler");
            retval = privilegeByCookieRequest(buffer, send);
            break;

        default:
            LogDebug("Error, unknown function called by client");
            retval = false;
            break;
        };
    } else if (interfaceID == INTERFACE_CHECK_TMP) {
        //TODO: Merge this interface with INTERFACE_CHECK after INTERFACE_CHECK will be secured by smack 
        switch(msgType) {
        case CookieCall::CHECK_UID:
            LogDebug("Entering get-uid-by-cookie side handler");
            retval = uidByCookieRequest(buffer, send);
            break;

        case CookieCall::CHECK_GID:
            LogDebug("Entering get-gid-by-cookie side handler");
            retval = gidByCookieRequest(buffer, send);
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

    if (retval) {
        //send response
        m_serviceManager->Write(conn, send.Pop());
    } else {
        LogDebug("Closing socket because of error");
        m_serviceManager->Close(conn);
    }

    // Each time you add one cookie check 2 others.
    if (removeGarbage)
        m_cookieJar.GarbageCollector(2);

    return retval;
}

bool CookieService::cookieRequest(MessageBuffer &send, int socket)
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

bool CookieService::pidByCookieRequest(MessageBuffer &buffer, MessageBuffer &send)
{
    std::vector<char> cookieKey;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL) {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        Serialization::Serialize(send, (int)searchResult->pid);
    } else {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE);
    }

    return true;
}

bool CookieService::smackLabelByCookieRequest(MessageBuffer &buffer, MessageBuffer &send)
{
    std::vector<char> cookieKey;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
    } Catch (MessageBuffer::Exception::Base) {
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

bool CookieService::privilegeByCookieGidRequest(MessageBuffer &buffer, MessageBuffer &send)
{
    std::vector<char> cookieKey;
    int gid;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
        Deserialization::Deserialize(buffer, gid);
    } Catch (MessageBuffer::Exception::Base) {
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

bool CookieService::privilegeByCookieRequest(MessageBuffer &buffer, MessageBuffer &send)
{
    std::vector<char> cookieKey;
    std::string subject;
    std::string object;
    std::string access;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
        Deserialization::Deserialize(buffer, object);
        Deserialization::Deserialize(buffer, access);
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL) {
        if (!smack_check()) {
            Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        } else {
            subject = searchResult->smackLabel;
            int retval;

            if ((retval = smack_have_access(subject.c_str(), object.c_str(), access.c_str())) == 1)
                Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
            else {
                Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_ACCESS_DENIED);
                LogSmackAudit("SS_SMACK: "
                    << " subject=" << subject
                    << ", object=" << object
                    << ", access=" << access
                    << ", result=" << retval);
            }
        }
    } else {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE);
    }

    return true;
}

bool CookieService::uidByCookieRequest(MessageBuffer &buffer, MessageBuffer &send)
{
    std::vector<char> cookieKey;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL) {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        Serialization::Serialize(send, (int)searchResult->uid);
    } else {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE);
    }

    return true;
}

bool CookieService::gidByCookieRequest(MessageBuffer &buffer, MessageBuffer &send)
{
    std::vector<char> cookieKey;

    Try {
        Deserialization::Deserialize(buffer, cookieKey);
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        return false;
    }

    Cookie searchPattern;
    searchPattern.cookieId = cookieKey;

    const Cookie *searchResult = m_cookieJar.SearchCookie(searchPattern, CompareType::COOKIE_ID);

    if (searchResult != NULL) {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_SUCCESS);
        Serialization::Serialize(send, (int)searchResult->gid);
    } else {
        Serialization::Serialize(send, (int)SECURITY_SERVER_API_ERROR_NO_SUCH_COOKIE);
    }

    return true;
}

} // namespace SecurityServer

