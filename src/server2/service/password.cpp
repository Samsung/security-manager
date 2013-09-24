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
 * @file        password.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of password service
 */

#include <iostream>
#include <string>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <password.h>

#include <security-server.h>
#include <password-exception.h>

namespace SecurityServer {

namespace {
// Service may open more than one socket.
// These ID's will be assigned to sockets
// and will be used only by service.
// When new connection arrives, AcceptEvent
// will be generated with proper ID to inform
// service about input socket.
//
// Please note: SocketManager does not use it and
// does not check it in any way.
//
// If your service requires only one socket
// (uses only one socket labeled with smack)
// you may ignore this ID (just pass 0)
const InterfaceID SOCKET_ID_CHECK   = 0;
const InterfaceID SOCKET_ID_SET     = 1;

} // namespace anonymous

GenericSocketService::ServiceDescriptionVector PasswordService::GetServiceDescription()
{
    return ServiceDescriptionVector {
        {SERVICE_SOCKET_PASSWD_CHECK, "security-server::api-password-check", SOCKET_ID_CHECK},
        {SERVICE_SOCKET_PASSWD_SET,   "security-server::api-password-set",   SOCKET_ID_SET}
    };
}

void PasswordService::accept(const AcceptEvent &event)
{
    LogSecureDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);

    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void PasswordService::write(const WriteEvent &event)
{
    LogSecureDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void PasswordService::process(const ReadEvent &event)
{
    LogSecureDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, info.buffer, info.interfaceID));
}

void PasswordService::close(const CloseEvent &event)
{
    LogSecureDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

int PasswordService::processCheckFunctions(PasswordHdrs hdr, MessageBuffer& buffer,
                                            unsigned int &cur_att, unsigned int &max_att,
                                            unsigned int &exp_time)
{
    int result = SECURITY_SERVER_API_ERROR_SERVER_ERROR;

    switch (hdr) {
        case PasswordHdrs::HDR_IS_PWD_VALID:
            result = m_pwdManager.isPwdValid(cur_att, max_att, exp_time);
            break;

        case PasswordHdrs::HDR_CHK_PWD: {
            std::string challenge;
            Deserialization::Deserialize(buffer, challenge);
            result = m_pwdManager.checkPassword(challenge, cur_att, max_att, exp_time);
            break;
        }

        default:
            LogError("Unknown msg header.");
            Throw(Exception::IncorrectHeader);
    }

    return result;
}

int PasswordService::processSetFunctions(PasswordHdrs hdr, MessageBuffer& buffer)
{
    int result = SECURITY_SERVER_API_ERROR_SERVER_ERROR;

    std::string curPwd, newPwd;
    unsigned int rec_att = 0, rec_days = 0, rec_max_challenge = 0, rec_history = 0;

    switch(hdr) {
        case PasswordHdrs::HDR_SET_PWD:
            Deserialization::Deserialize(buffer, curPwd);
            Deserialization::Deserialize(buffer, newPwd);
            Deserialization::Deserialize(buffer, rec_att);
            Deserialization::Deserialize(buffer, rec_days);
            result = m_pwdManager.setPassword(curPwd, newPwd, rec_att, rec_days);
            break;

        case PasswordHdrs::HDR_SET_PWD_VALIDITY:
            Deserialization::Deserialize(buffer, rec_days);
            result = m_pwdManager.setPasswordValidity(rec_days);
            break;

        case PasswordHdrs::HDR_SET_PWD_MAX_CHALLENGE:
            Deserialization::Deserialize(buffer, rec_max_challenge);
            result = m_pwdManager.setPasswordMaxChallenge(rec_max_challenge);
            break;

        case PasswordHdrs::HDR_RST_PWD:
            Deserialization::Deserialize(buffer, newPwd);
            Deserialization::Deserialize(buffer, rec_att);
            Deserialization::Deserialize(buffer, rec_days);
            result = m_pwdManager.resetPassword(newPwd, rec_att, rec_days);
            break;

        case PasswordHdrs::HDR_SET_PWD_HISTORY:
            Deserialization::Deserialize(buffer, rec_history);
            result = m_pwdManager.setPasswordHistory(rec_history);
            break;

        default:
            LogError("Unknown msg header.");
            Throw(Exception::IncorrectHeader);
    }

    return result;
}

bool PasswordService::processOne(const ConnectionID &conn, MessageBuffer &buffer,
                                 InterfaceID interfaceID)
{
    LogSecureDebug("Iteration begin");

    MessageBuffer sendBuffer;

    int retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
    unsigned int cur_att = 0, max_att = 0, exp_time = 0;

    if (!buffer.Ready())
        return false;

    Try {       //try..catch for MessageBuffer errors, closes connection when exception is thrown
        int tempHdr;
        Deserialization::Deserialize(buffer, tempHdr);
        PasswordHdrs hdr = static_cast<PasswordHdrs>(tempHdr);

        try {   //try..catch for internal service errors, assigns error code for returning.
            switch (interfaceID) {
                case SOCKET_ID_CHECK:
                    retCode = processCheckFunctions(hdr, buffer, cur_att, max_att, exp_time);
                    break;

                case SOCKET_ID_SET:
                    retCode = processSetFunctions(hdr, buffer);
                    break;

                default:
                    LogError("Wrong interfaceID.");
                    Throw(Exception::IncorrectHeader);
            }
        } catch (PasswordException::Base &e) {
            LogError("Password error: " << e.DumpToString());
            retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
        } catch (std::exception &e) {
            LogError("STD error: " << e.what());
            retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
        }

        //everything is OK, send return code and extra data
        Serialization::Serialize(sendBuffer, retCode);

        //Returning additional information should occur only when checking functions
        //are called, and under certain return values
        if(interfaceID == SOCKET_ID_CHECK)
        {
            switch(retCode)
            {
            case SECURITY_SERVER_API_ERROR_PASSWORD_EXIST:
            case SECURITY_SERVER_API_ERROR_PASSWORD_MISMATCH:
            case SECURITY_SERVER_API_ERROR_PASSWORD_MAX_ATTEMPTS_EXCEEDED:
            case SECURITY_SERVER_API_ERROR_PASSWORD_EXPIRED:
                Serialization::Serialize(sendBuffer, cur_att);
                Serialization::Serialize(sendBuffer, max_att);
                Serialization::Serialize(sendBuffer, exp_time);
                break;

            case SECURITY_SERVER_API_SUCCESS:
                if(hdr == PasswordHdrs::HDR_CHK_PWD) {
                    Serialization::Serialize(sendBuffer, cur_att);
                    Serialization::Serialize(sendBuffer, max_att);
                    Serialization::Serialize(sendBuffer, exp_time);
                }
                break;

            default:
                break;
            }
        }

        m_serviceManager->Write(conn, sendBuffer.Pop());
    } Catch (MessageBuffer::Exception::Base) {
        LogError("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    } Catch (PasswordService::Exception::Base) {
        LogError("Incorrect message header. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }



    return true;
}

} // namespace SecurityServer

