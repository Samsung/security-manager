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
 * @file        privilege-by-pid.cpp
 * @author      Jan Cybulski (j.cybulski@samsung.com)
 * @version     1.0
 * @brief       Implementation of check-privilege-by-pid service.
 */

#include <sys/smack.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>

#include <protocols.h>
#include <privilege-by-pid.h>

#include <security-server.h>
#include <security-server-util.h>
#include <smack-check.h>

#include <privilege-control.h>

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector PrivilegeByPidService::GetServiceDescription() {
    //TODO: after enabled smack protection for api use "security-server::api-privilege-by-pid"
    return ServiceDescriptionVector
        {{SERVICE_SOCKET_PRIVILEGE_BY_PID, "*" }};
}

void PrivilegeByPidService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
}

void PrivilegeByPidService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

bool PrivilegeByPidService::processOne(const ConnectionID &conn, MessageBuffer &buffer) {
    LogDebug("Iteration begin");

    int retval;
    int pid;
    std::string object;
    std::string access_rights;
    char subject[SMACK_LABEL_LEN + 1] = {0};

    int retCode = SECURITY_SERVER_API_ERROR_SERVER_ERROR;


    if (!buffer.Ready()) {
        return false;
    }

    Try {
        Deserialization::Deserialize(buffer, pid);
        Deserialization::Deserialize(buffer, object);
        Deserialization::Deserialize(buffer, access_rights);
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    if (smack_check()) {
        retval = smack_pid_have_access(pid, object.c_str(), access_rights.c_str());
        LogDebug("smack_pid_have_access returned " << retval);

        if (get_smack_label_from_process(pid, subject) != PC_OPERATION_SUCCESS) {
            // subject label is set to empty string
            LogError("get_smack_label_from_process failed. Subject label has not been read.");
        } else {
            SECURE_SLOGD("Subject label of client PID %d is: %s", pid, subject);
        }
    } else {
        LogDebug("SMACK is not available. Subject label has not been read.");
        retval = 1;
    }

//    char *path = read_exe_path_from_proc(pid);
//
//    if (retval > 0)
//        LogDebug("SS_SMACK: "
//                << "caller_pid=" << pid
//                << ", subject=" << subject
//                << ", object=" << object
//                << ", access=" << access_rights
//                << ", result=" << retval
//                << ", caller_path=" << path);
//    else
//        LogError("SS_SMACK: "
//                << "caller_pid=" << pid
//                << ", subject=" << subject
//                << ", object=" << object
//                << ", access=" << access_rights
//                << ", result=" << retval
//                << ", caller_path=" << path);
//
//    if (path != NULL)
//        free(path);

    if (retval == 1)   //there is permission
        retCode = SECURITY_SERVER_API_SUCCESS;
    else                //there is no permission
        retCode = SECURITY_SERVER_API_ERROR_ACCESS_DENIED;

    MessageBuffer sendBuffer;
    Serialization::Serialize(sendBuffer, retCode);
    m_serviceManager->Write(conn, sendBuffer.Pop());
    return true;
}

void PrivilegeByPidService::process(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &buffer = m_messageBufferMap[event.connectionID.counter];
    buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, buffer));
}

void PrivilegeByPidService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_messageBufferMap.erase(event.connectionID.counter);
}

} // namespace SecurityServer

