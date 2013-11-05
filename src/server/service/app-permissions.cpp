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
 * @file        app-permissions.cpp
 * @author      Pawel Polawski (pawel.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contain implementation of security_server_app_enable_permissions
 *              and security_server_app_disable_permissions on server side
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
    LogDebug("Iteration begin");

    //waiting for all data
    if (!buffer.Ready()) {
        return false;
    }

    LogDebug("Entering app_permissions server side handler");

    switch(interfaceID) {
    case CHANGE_APP_PERMISSIONS:
        return processPermissionsChange(conn, buffer);

    case CHECK_APP_PRIVILEGE:
        return processCheckAppPrivilege(conn, buffer);

    default:
        LogDebug("Unknown interfaceId. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }
}

bool AppPermissionsService::processPermissionsChange(const ConnectionID &conn, MessageBuffer &buffer)
{
    MessageBuffer send;
    std::vector<std::string> permissions_list;
    std::string app_id;
    int persistent;
    size_t iter;
    int result = SECURITY_SERVER_API_ERROR_SERVER_ERROR;
    app_type_t app_type;
    AppPermissionsAction appPermAction;

    LogDebug("Processing permissions change request");

    //receive data from buffer and check MSG_ID
    Try {
        int temp;
        Deserialization::Deserialize(buffer, temp);                 //receive MSG_ID
        appPermAction = (AppPermissionsAction)temp;

        if (appPermAction == AppPermissionsAction::ENABLE)      //persistent is only in APP_ENABLE frame
            Deserialization::Deserialize(buffer, persistent);

        Deserialization::Deserialize(buffer, temp);
        app_type = (app_type_t)temp;
        Deserialization::Deserialize(buffer, app_id);
        Deserialization::Deserialize(buffer, permissions_list);
    } Catch (MessageBuffer::Exception::Base) {
        LogDebug("Broken protocol. Closing socket.");
        m_serviceManager->Close(conn);
        return false;
    }

    //+1 bellow is for NULL pointer at the end
    std::unique_ptr<const char *[]> perm_list (new (std::nothrow) const char *[permissions_list.size() + 1]);
    if (NULL == perm_list.get()) {
        LogError("Allocation error");
        m_serviceManager->Close(conn);
        return false;
    }

    //print received data
    LogDebug("app_type: " << (int)app_type);
    if (appPermAction == AppPermissionsAction::ENABLE)    //persistent is only in APP_ENABLE frame
        LogDebug("persistent: " << persistent);
    LogDebug("app_id: " << app_id);

    //left one free pointer for the NULL at the end
    for (iter = 0; iter < permissions_list.size(); ++iter) {
        LogDebug("perm_list[" << iter << "]: " << permissions_list[iter]);
        perm_list[iter] = (permissions_list[iter]).c_str();
    }
    //put the NULL at the end
    perm_list[iter] = NULL;

    //use received data
    if (appPermAction == AppPermissionsAction::ENABLE) {
        LogDebug("Calling perm_app_enable_permissions()");
        result = perm_app_enable_permissions(app_id.c_str(), app_type, perm_list.get(), persistent);
        LogDebug("perm_app_enable_permissions() returned: " << result);
    } else {
        LogDebug("Calling perm_app_disable_permissions()");
        result = perm_app_disable_permissions(app_id.c_str(), app_type, perm_list.get());
        LogDebug("perm_app_disable_permissions() returned: " << result);
    }

    //send response
    Serialization::Serialize(send, privilegeToSecurityServerError(result));
    m_serviceManager->Write(conn, send.Pop());
    return true;
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
