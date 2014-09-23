/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
 *
 *	Security Manager library header
 */
/*
 * @file        client-security-manager.cpp
 * @author      Pawel Polawski <p.polawski@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       This file contain client side implementation of security-manager API
 */

#include <cstdio>
#include <utility>

#include <unistd.h>
#include <grp.h>
#include <sys/types.h>
#include <sys/smack.h>
#include <sys/capability.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <smack-common.h>

#include <security-manager.h>



SECURITY_MANAGER_API
int security_manager_app_inst_req_new(app_inst_req **pp_req)
{
    if (!pp_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    try {
        *pp_req = new app_inst_req;
    } catch (std::bad_alloc& ex) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    }


    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
void security_manager_app_inst_req_free(app_inst_req *p_req)
{
    delete p_req;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_set_app_id(app_inst_req *p_req, const char *app_id)
{
    if (!p_req || !app_id)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->appId = app_id;

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_set_pkg_id(app_inst_req *p_req, const char *pkg_id)
{
    if (!p_req || !pkg_id)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->pkgId = pkg_id;

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_add_privilege(app_inst_req *p_req, const char *privilege)
{
    if (!p_req || !privilege)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->privileges.push_back(privilege);

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_add_path(app_inst_req *p_req, const char *path, const int path_type)
{
    if (!p_req || !path || (path_type < 0) || (path_type >= SECURITY_MANAGER_ENUM_END))
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->appPaths.push_back(std::make_pair(path, path_type));

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_install(const app_inst_req *p_req)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;

    return try_catch([&] {
        //checking parameters
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->appId.empty() || p_req->pkgId.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        //put data into buffer
        Serialization::Serialize(send, (int)SecurityModuleCall::APP_INSTALL);
        Serialization::Serialize(send, p_req->appId);
        Serialization::Serialize(send, p_req->pkgId);
        Serialization::Serialize(send, p_req->privileges);
        Serialization::Serialize(send, p_req->appPaths);

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        switch(retval) {
            case SECURITY_MANAGER_API_SUCCESS:
                return SECURITY_MANAGER_SUCCESS;
            case SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED:
                return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
            default:
                return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

    });
}

SECURITY_MANAGER_API
int security_manager_app_uninstall(const app_inst_req *p_req)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;

    return try_catch([&] {
        //checking parameters
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->appId.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        //put data into buffer
        Serialization::Serialize(send, (int)SecurityModuleCall::APP_UNINSTALL);
        Serialization::Serialize(send, p_req->appId);

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_MANAGER_API_SUCCESS)
            return SECURITY_MANAGER_ERROR_UNKNOWN;

        return SECURITY_MANAGER_SUCCESS;;
    });
}

SECURITY_MANAGER_API
int security_manager_get_app_pkgid(char **pkg_id, const char *app_id)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;

    LogDebug("security_manager_get_app_pkgid() called");

    return try_catch([&] {
        //checking parameters

        if (app_id == NULL) {
            LogError("security_manager_app_get_pkgid: app_id is NULL");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (pkg_id == NULL) {
            LogError("security_manager_app_get_pkgid: pkg_id is NULL");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_GET_PKGID));
        Serialization::Serialize(send, std::string(app_id));

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_MANAGER_API_SUCCESS)
            return SECURITY_MANAGER_ERROR_UNKNOWN;

        std::string pkgIdString;
        Deserialization::Deserialize(recv, pkgIdString);
        if (pkgIdString.empty()) {
            LogError("Unexpected empty pkgId");
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        *pkg_id = strdup(pkgIdString.c_str());
        if (*pkg_id == NULL) {
            LogError("Failed to allocate memory for pkgId");
            return SECURITY_MANAGER_ERROR_MEMORY;
        }

        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_set_process_label_from_binary(const char *path)
{
    char *smack_label;
    int ret;

    LogDebug("security_manager_set_process_label_from_binary() called");

    if (smack_smackfs_path() == NULL)
        return SECURITY_MANAGER_SUCCESS;

    if (path == NULL) {
        LogError("security_manager_set_process_label_from_binary: path is NULL");
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    }

    ret = SecurityManager::getSmackLabelFromBinary(&smack_label, path);
    if (ret == SECURITY_MANAGER_SUCCESS && smack_label != NULL) {
        if (smack_set_label_for_self(smack_label) != 0) {
            ret = SECURITY_MANAGER_ERROR_UNKNOWN;
            LogError("Failed to set smack label " << smack_label << " for current process");
        }
        free(smack_label);
    }

    return ret;
}

SECURITY_MANAGER_API
int security_manager_set_process_label_from_appid(const char *app_id)
{
    char *pkg_id;
    int ret;
    std::string appLabel;

    LogDebug("security_manager_set_process_label_from_appid() called");

    if (smack_smackfs_path() == NULL)
        return SECURITY_MANAGER_SUCCESS;

    ret = security_manager_get_app_pkgid(&pkg_id, app_id);
    if (ret != SECURITY_MANAGER_SUCCESS) {
        return ret;
    }

    if (SecurityManager::generateAppLabel(std::string(pkg_id), appLabel)) {
        if (smack_set_label_for_self(appLabel.c_str()) != 0) {
            LogError("Failed to set smack label " << appLabel << " for current process");
            ret = SECURITY_MANAGER_ERROR_UNKNOWN;
        }
    }
    else {
        ret = SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    free(pkg_id);
    return ret;
}

SECURITY_MANAGER_API
int security_manager_set_process_groups_from_appid(const char *app_id)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    int ret;

    LogDebug("security_manager_set_process_groups_from_appid() called");

    return try_catch([&] {
        //checking parameters

        if (app_id == nullptr) {
            LogError("app_id is NULL");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_GET_GROUPS));
        Serialization::Serialize(send, std::string(app_id));

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_MANAGER_API_SUCCESS)
            return SECURITY_MANAGER_ERROR_UNKNOWN;

        //How many new groups?
        int newGroupsCnt;
        Deserialization::Deserialize(recv, newGroupsCnt);

        //And how many groups do we belong to already?
        int oldGroupsCnt;
        ret = getgroups(0, nullptr);
        if (ret == -1) {
            LogError("Unable to get list of current supplementary groups: " <<
                strerror(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }
        oldGroupsCnt = ret;

        //Allocate an array for both old and new groups gids
        std::unique_ptr<gid_t[]> groups(new gid_t[oldGroupsCnt + newGroupsCnt]);
        if (!groups.get()) {
            LogError("Memory allocation failed.");
            return SECURITY_MANAGER_ERROR_MEMORY;
        }

        //Get the old groups from process
        ret = getgroups(oldGroupsCnt, groups.get());
        if (ret == -1) {
            LogError("Unable to get list of current supplementary groups: " <<
                strerror(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        //Get the new groups from server response
        for (int i = 0; i < newGroupsCnt; ++i) {
            gid_t gid;
            Deserialization::Deserialize(recv, gid);
            groups.get()[oldGroupsCnt + i] = gid;
            LogDebug("Adding process to group " << gid);
        }

        //Apply the modified groups list
        ret = setgroups(oldGroupsCnt + newGroupsCnt, groups.get());
        if (ret == -1) {
            LogError("Unable to get list of current supplementary groups: " <<
                strerror(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_drop_process_privileges(void)
{
    LogDebug("security_manager_drop_process_privileges() called");

    int ret;
    cap_t cap = cap_init();
    if (!cap) {
        LogError("Unable to allocate capability object");
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    ret = cap_clear(cap);
    if (ret) {
        LogError("Unable to initialize capability object");
        cap_free(cap);
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    ret = cap_set_proc(cap);
    if (ret) {
        LogError("Unable to drop process capabilities");
        cap_free(cap);
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    cap_free(cap);
    return SECURITY_MANAGER_SUCCESS;
}
