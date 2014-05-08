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
 * @file        app-permissions.cpp
 * @author      Pawel Polawski (pawel.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of security_server_app_has_permission
 *              on server side
 */

#include <memory>
#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <privilege-control.h>

#include <sys/smack.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <app-permissions.h>
#include <protocols.h>
#include <security-server.h>
#include <privilege-control.h>

namespace {

int privilegeToSecurityServerError(int error) {
    switch (error) {
    case PC_OPERATION_SUCCESS:  return SECURITY_SERVER_API_SUCCESS;
    case PC_ERR_FILE_OPERATION: return SECURITY_SERVER_API_ERROR_UNKNOWN;
    case PC_ERR_MEM_OPERATION:  return SECURITY_SERVER_API_ERROR_OUT_OF_MEMORY;
    case PC_ERR_NOT_PERMITTED:  return SECURITY_SERVER_API_ERROR_ACCESS_DENIED;
    case PC_ERR_INVALID_PARAM:  return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
    case PC_ERR_INVALID_OPERATION:
    case PC_ERR_DB_OPERATION:
    default:
        ;
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}

// interface ids
const SecurityServer::InterfaceID CHANGE_APP_PERMISSIONS = 0;
const SecurityServer::InterfaceID CHECK_APP_PRIVILEGE = 1;

} // namespace anonymous

namespace SecurityServer {

GenericSocketService::ServiceDescriptionVector AppPermissionsService::GetServiceDescription() {
    return ServiceDescriptionVector {
        { SERVICE_SOCKET_APP_PERMISSIONS,
          "security-server::api-app-permissions",
          CHANGE_APP_PERMISSIONS },
        { SERVICE_SOCKET_APP_PRIVILEGE_BY_NAME,
          "security-server::api-app-privilege-by-name",
          CHECK_APP_PRIVILEGE }
    };
}

void AppPermissionsService::accept(const AcceptEvent &event) {
    LogDebug("Accept event. ConnectionID.sock: " << event.connectionID.sock
        << " ConnectionID.counter: " << event.connectionID.counter
        << " ServiceID: " << event.interfaceID);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.interfaceID = event.interfaceID;
}

void AppPermissionsService::write(const WriteEvent &event) {
    LogDebug("WriteEvent. ConnectionID: " << event.connectionID.sock <<
        " Size: " << event.size << " Left: " << event.left);
    if (event.left == 0)
        m_serviceManager->Close(event.connectionID);
}

void AppPermissionsService::process(const ReadEvent &event) {
    LogDebug("Read event for counter: " << event.connectionID.counter);
    auto &info = m_connectionInfoMap[event.connectionID.counter];
    info.buffer.Push(event.rawBuffer);

    // We can get several requests in one package.
    // Extract and process them all
    while(processOne(event.connectionID, info.buffer, info.interfaceID));
}

void AppPermissionsService::close(const CloseEvent &event) {
    LogDebug("CloseEvent. ConnectionID: " << event.connectionID.sock);
    m_connectionInfoMap.erase(event.connectionID.counter);
}

bool AppPermissionsService::processOne(const ConnectionID &conn,
                                       MessageBuffer &buffer,
                                       InterfaceID interfaceID)
{
    LogDebug("Begin of an iteration");

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    LogDebug("Entering app_permissions server side handler");

    switch(interfaceID) {

    case CHECK_APP_PRIVILEGE:
        return processCheckAppPrivilege(conn, buffer);

    default:
        LogDebug("Unknown interfaceId. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }
}

bool AppPermissionsService::processCheckAppPrivilege(const ConnectionID &conn, MessageBuffer &buffer)
{
    MessageBuffer send;
    std::string privilege_name;
    std::string app_id;
    int result = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
    app_type_t app_type;
    bool has_permission = false;
    PrivilegeCheckHdrs checkType = PrivilegeCheckHdrs::CHECK_GIVEN_APP;

    LogDebug("Processing app privilege check request");

    //receive data from buffer
    Try {
        int temp;
        Deserialization::Deserialize(buffer, temp); // call type
        checkType = static_cast<PrivilegeCheckHdrs>(temp);
        LogDebug("App privilege check call type: "
                 << (checkType == PrivilegeCheckHdrs::CHECK_GIVEN_APP ?
                     "CHECK_GIVEN_APP":"CHECK_CALLER_APP"));
        if (checkType == PrivilegeCheckHdrs::CHECK_GIVEN_APP) { //app_id present only in this case
            Deserialization::Deserialize(buffer, app_id); //get app id
        }
        Deserialization::Deserialize(buffer, temp); //get app type
        app_type = static_cast<app_type_t>(temp);

        Deserialization::Deserialize(buffer, privilege_name); //get privilege name
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    if (checkType == PrivilegeCheckHdrs::CHECK_CALLER_APP) { //get sender app_id in this case
        char *label = NULL;
        if (smack_new_label_from_socket(conn.sock, &label) < 0) {
            LogDebug("Error in smack_new_label_from_socket(): "
                     "client label is unknown. Sending error response.");
            Serialization::Serialize(send, SECURITY_SERVER_API_ERROR_GETTING_SOCKET_LABEL_FAILED);
            m_serviceManager->Write(conn, send.Pop());
            return false;
        } else {
            app_id = label;
            free(label);
        }
    } //end if

    //print received data
    LogDebug("app_id: " << app_id);
    LogDebug("app_type: " << static_cast<int>(app_type));
    LogDebug("privilege_name: " << privilege_name);

    LogDebug("Calling perm_app_has_permission()");
    result = perm_app_has_permission(app_id.c_str(), app_type, privilege_name.c_str(), &has_permission);
    LogDebug("perm_app_has_permission() returned: " << result << " , permission enabled: " << has_permission);

    //send response
    Serialization::Serialize(send, privilegeToSecurityServerError(result));
    Serialization::Serialize(send, static_cast<int>(has_permission));
    m_serviceManager->Write(conn, send.Pop());
    return true;
}

} // namespace SecurityServer
