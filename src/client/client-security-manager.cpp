/*
 *  Copyright (c) 2000 - 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <functional>
#include <memory>
#include <utility>

#include <unistd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/smack.h>
#include <sys/capability.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>
#include <smack-labels.h>
#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <service_impl.h>
#include <connection.h>
#include <zone-utils.h>

#include <security-manager.h>
#include <client-offline.h>

static const char *EMPTY = "";

/**
 * Mapping of lib_retcode error codes to theirs strings equivalents
 */
static std::map<enum lib_retcode, std::string> lib_retcode_string_map = {
    {SECURITY_MANAGER_SUCCESS, "Success"},
    {SECURITY_MANAGER_ERROR_UNKNOWN, "Unknown error"},
    {SECURITY_MANAGER_ERROR_INPUT_PARAM, "Invalid function parameter was given"},
    {SECURITY_MANAGER_ERROR_MEMORY, "Memory allocation error"},
    {SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE, "Incomplete data in application request"},
    {SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED, "User does not have sufficient "
                                                   "rigths to perform an operation"},
    {SECURITY_MANAGER_ERROR_ACCESS_DENIED, "Insufficient privileges"},
};

SECURITY_MANAGER_API
const char *security_manager_strerror(enum lib_retcode rc)
{
    try {
        return lib_retcode_string_map.at(rc).c_str();
    } catch (const std::out_of_range &e) {
        return "Unknown error code";
    }
}

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
    (*pp_req)->uid = geteuid();

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
void security_manager_app_inst_req_free(app_inst_req *p_req)
{
    delete p_req;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_set_uid(app_inst_req *p_req,
                                          const uid_t uid)
{
    if (!p_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->uid = uid;

    return SECURITY_MANAGER_SUCCESS;
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

    return try_catch([&] {
        //checking parameters
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->appId.empty() || p_req->pkgId.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        int retval;
        ClientOffline offlineMode;
        if (offlineMode.isOffline()) {
            retval = SecurityManager::ServiceImpl().appInstall(*p_req, geteuid(), false);
        } else {
            MessageBuffer send, recv;

            //put data into buffer
            Serialization::Serialize(send, (int)SecurityModuleCall::APP_INSTALL,
                p_req->appId, p_req->pkgId, p_req->privileges, p_req->appPaths, p_req->uid);

            //send buffer to server
            retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
            if (retval != SECURITY_MANAGER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << retval);
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }

            //receive response from server
            Deserialization::Deserialize(recv, retval);
        }
        switch(retval) {
            case SECURITY_MANAGER_API_SUCCESS:
                return SECURITY_MANAGER_SUCCESS;
            case SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED:
                return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;
            case SECURITY_MANAGER_API_ERROR_ACCESS_DENIED:
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
            case SECURITY_MANAGER_API_ERROR_INPUT_PARAM:
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
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
        Serialization::Serialize(send, (int)SecurityModuleCall::APP_UNINSTALL,
            p_req->appId);

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
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_GET_PKGID),
            std::string(app_id));

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

static bool setup_smack(const char *label)
{
    int labelSize = strlen(label);

    // Set Smack label for open socket file descriptors

    std::unique_ptr<DIR, std::function<int(DIR*)>> dir(
        opendir("/proc/self/fd"), closedir);
    if (!dir.get()) {
        LogError("Unable to read list of open file descriptors: " <<
            strerror(errno));
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    do {
        errno = 0;
        struct dirent *dirEntry = readdir(dir.get());
        if (dirEntry == nullptr) {
            if (errno == 0) // NULL return value also signals end of directory
                break;

            LogError("Unable to read list of open file descriptors: " <<
                strerror(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        // Entries with numerical names specify file descriptors, ignore the rest
        if (!isdigit(dirEntry->d_name[0]))
            continue;

        struct stat statBuf;
        int fd = atoi(dirEntry->d_name);
        int ret = fstat(fd, &statBuf);
        if (ret != 0) {
            LogWarning("fstat failed on file descriptor " << fd << ": " <<
                strerror(errno));
            continue;
        }
        if (S_ISSOCK(statBuf.st_mode)) {
            ret = fsetxattr(fd, XATTR_NAME_SMACKIPIN, label, labelSize, 0);
            if (ret != 0) {
                LogError("Setting Smack label failed on file descriptor " <<
                    fd << ": " << strerror(errno));
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }

            ret = fsetxattr(fd, XATTR_NAME_SMACKIPOUT, label, labelSize, 0);
            if (ret != 0) {
                LogError("Setting Smack label failed on file descriptor " <<
                    fd << ": " << strerror(errno));
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }
        }
    } while (true);

    // Set Smack label of current process
    smack_set_label_for_self(label);

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_set_process_label_from_appid(const char *app_id)
{
    int ret;
    std::string appLabel;

    LogDebug("security_manager_set_process_label_from_appid() called");

    if (smack_smackfs_path() == NULL)
        return SECURITY_MANAGER_SUCCESS;

    // FIXME Below modifications related to zones are temporary. Remove when Smack Namespaces
    //       are implemented.
    std::string zoneId;
    if (!getZoneIdFromPid(getpid(), zoneId)) {
        LogError("Failed to get ID of zone");
        return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;
    }

    try {
        appLabel = SecurityManager::zoneSmackLabelGenerate(
                SecurityManager::SmackLabels::generateAppLabel(app_id), zoneId);

    } catch (...) {
        LogError("Failed to generate smack label for appId: " << app_id);
        return SECURITY_MANAGER_API_ERROR_NO_SUCH_OBJECT;
    }

    if ((ret = setup_smack(appLabel.c_str())) != SECURITY_MANAGER_SUCCESS) {
        LogError("Failed to set smack label " << appLabel << " for current process");
        return ret;
    }

    return SECURITY_MANAGER_SUCCESS;
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
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_GET_GROUPS),
            std::string(app_id));

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_API_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_MANAGER_API_SUCCESS) {
            LogError("Failed to get list of groups from security-manager service. Error code: " << retval);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

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

SECURITY_MANAGER_API
int security_manager_prepare_app(const char *app_id)
{
    LogDebug("security_manager_prepare_app() called");
    int ret;

    ret = security_manager_set_process_label_from_appid(app_id);
    if (ret != SECURITY_MANAGER_SUCCESS)
        return ret;

    ret = security_manager_set_process_groups_from_appid(app_id);
    if (ret != SECURITY_MANAGER_SUCCESS) {
        LogWarning("Unable to setup process groups for application. Privileges with direct access to resources will not work.");
        ret = SECURITY_MANAGER_SUCCESS;
    }

    ret = security_manager_drop_process_privileges();
    return ret;
}

SECURITY_MANAGER_API
int security_manager_user_req_new(user_req **pp_req)
{
    if (!pp_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    try {
        *pp_req = new user_req;
    } catch (std::bad_alloc& ex) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    }
    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
void security_manager_user_req_free(user_req *p_req)
{
    delete p_req;
}

SECURITY_MANAGER_API
int security_manager_user_req_set_uid(user_req *p_req, uid_t uid)
{
    if (!p_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->uid = uid;

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_user_req_set_user_type(user_req *p_req, security_manager_user_type utype)
{
    if (!p_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->utype = static_cast<int>(utype);

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_user_add(const user_req *p_req)
{
    using namespace SecurityManager;
    if (!p_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    return try_catch([&] {
        int retval;
        ClientOffline offlineMode;
        if (offlineMode.isOffline()) {
            retval = SecurityManager::ServiceImpl().userAdd(p_req->uid, p_req->utype, geteuid(),
                                                           false);
        } else {
            MessageBuffer send, recv;
            //server is working

            //put data into buffer
            Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::USER_ADD),
                p_req->uid, p_req->utype);

            //send buffer to server
            retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
            if (retval != SECURITY_MANAGER_API_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << retval);
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }

            //receive response from server
            Deserialization::Deserialize(recv, retval);
        }
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
int security_manager_user_delete(const user_req *p_req)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    if (!p_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    return try_catch([&] {

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::USER_DELETE),
            p_req->uid);

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


/***************************POLICY***************************************/

SECURITY_MANAGER_API
int security_manager_policy_update_req_new(policy_update_req **pp_req)
{
    if (!pp_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    try {
        *pp_req = new policy_update_req;
    } catch (std::bad_alloc& ex) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
void security_manager_policy_update_req_free(policy_update_req *p_req)
{
    delete p_req;
}

SECURITY_MANAGER_API
int security_manager_policy_update_send(policy_update_req *p_req)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;

    if (p_req == nullptr || p_req->units.size() == 0)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    return try_catch([&] {

        //put request into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::POLICY_UPDATE),
            p_req->units);

        //send it to server
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
            case SECURITY_MANAGER_API_ERROR_ACCESS_DENIED:
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
            default:
                return SECURITY_MANAGER_ERROR_UNKNOWN;
        }
    });
}

static inline int security_manager_get_policy_internal(
        SecurityManager::SecurityModuleCall call_type,
        policy_entry *p_filter,
        policy_entry ***ppp_privs_policy,
        size_t *p_size)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;

    if (ppp_privs_policy == nullptr
        || p_size == nullptr
        || p_filter == nullptr)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    return try_catch([&] {
        //put request into buffer
        Serialization::Serialize(send, static_cast<int>(call_type),
            *p_filter);

        //send it to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_API_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }
        //receive response from server
        Deserialization::Deserialize(recv, retval);
        switch (retval) {
            case SECURITY_MANAGER_API_SUCCESS: {
                //extract and allocate buffers for privs policy entries
                int entriesCnt = 0;
                policy_entry **entries = nullptr;
                try {
                    Deserialization::Deserialize(recv, entriesCnt);
                    entries = new policy_entry*[entriesCnt]();
                    for (int i = 0; i < entriesCnt; ++i) {
                        entries[i] = new policy_entry;
                        Deserialization::Deserialize(recv, entries[i]);
                    };
                } catch (...) {
                    LogError("Error while parsing server response");
                    for (int i = 0; i < entriesCnt; ++i)
                        delete(entries[i]);
                    delete[] entries;
                    return SECURITY_MANAGER_ERROR_UNKNOWN;
                }
                *p_size = entriesCnt;
                *ppp_privs_policy = entries;
                return SECURITY_MANAGER_SUCCESS;
            }
            case SECURITY_MANAGER_API_ERROR_AUTHENTICATION_FAILED:
                return SECURITY_MANAGER_ERROR_AUTHENTICATION_FAILED;

            case SECURITY_MANAGER_API_ERROR_ACCESS_DENIED:
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;

            default:
                return SECURITY_MANAGER_ERROR_UNKNOWN;
        }
    });
}

SECURITY_MANAGER_API
int security_manager_get_configured_policy_for_admin(
        policy_entry *p_filter,
        policy_entry ***ppp_privs_policy,
        size_t *p_size)
{
    return security_manager_get_policy_internal(SecurityModuleCall::GET_CONF_POLICY_ADMIN, p_filter, ppp_privs_policy, p_size);
}

SECURITY_MANAGER_API
int security_manager_get_configured_policy_for_self(
        policy_entry *p_filter,
        policy_entry ***ppp_privs_policy,
        size_t *p_size)
{
    return security_manager_get_policy_internal(SecurityModuleCall::GET_CONF_POLICY_SELF, p_filter, ppp_privs_policy, p_size);
}

SECURITY_MANAGER_API
int security_manager_get_policy(
        policy_entry *p_filter,
        policy_entry ***ppp_privs_policy,
        size_t *p_size)
{
    return security_manager_get_policy_internal(SecurityModuleCall::GET_POLICY, p_filter, ppp_privs_policy, p_size);
};

SECURITY_MANAGER_API
int security_manager_policy_entry_new(policy_entry **p_entry)
{
    if (!p_entry)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    try {
        *p_entry = new policy_entry;
    } catch (std::bad_alloc& ex) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
void security_manager_policy_entry_free(policy_entry *p_entry)
{
    delete p_entry;
}

SECURITY_MANAGER_API
int security_manager_policy_entry_set_application(policy_entry *p_entry, const char *app_id)
{
    if (!p_entry)
        return  SECURITY_MANAGER_ERROR_INPUT_PARAM;
    p_entry->appId = app_id;
    return  SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_policy_entry_set_user(policy_entry *p_entry, const char *user)
{
    if (!p_entry)
        return  SECURITY_MANAGER_ERROR_INPUT_PARAM;
    p_entry->user = user;
    return  SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_policy_entry_set_privilege(policy_entry *p_entry, const char *privilege)
{
    if (!p_entry)
        return  SECURITY_MANAGER_ERROR_INPUT_PARAM;
    p_entry->privilege = privilege;
    return  SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_policy_entry_set_level(policy_entry *p_entry, const char *policy_level)
{
    if (!p_entry)
        return  SECURITY_MANAGER_ERROR_INPUT_PARAM;
    p_entry->currentLevel = policy_level;
    p_entry->maxLevel = EMPTY;
    return  SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_policy_entry_admin_set_level(policy_entry *p_entry, const char *policy_level)
{
    if (!p_entry)
        return  SECURITY_MANAGER_ERROR_INPUT_PARAM;
    p_entry->maxLevel = policy_level;
    p_entry->currentLevel = EMPTY;
    return  SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_policy_update_req_add_entry(policy_update_req *p_req, const policy_entry *p_entry)
{
    if (!p_entry || !p_req)
        return  SECURITY_MANAGER_ERROR_INPUT_PARAM;
    p_req->units.push_back(p_entry);

    return  SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
const char *security_manager_policy_entry_get_user(policy_entry *p_entry)
{
    return p_entry ? p_entry->user.c_str() : nullptr;
}

SECURITY_MANAGER_API
const char *security_manager_policy_entry_get_application(policy_entry *p_entry)
{
    return p_entry ? p_entry->appId.c_str() : nullptr;
}
SECURITY_MANAGER_API
const char *security_manager_policy_entry_get_privilege(policy_entry *p_entry)
{
    return p_entry ? p_entry->privilege.c_str() : nullptr;
}
SECURITY_MANAGER_API
const char *security_manager_policy_entry_get_level(policy_entry *p_entry)
{
    return p_entry ? p_entry->currentLevel.c_str() : nullptr;
}

SECURITY_MANAGER_API
const char *security_manager_policy_entry_get_max_level(policy_entry *p_entry)
{
    return p_entry ? p_entry->maxLevel.c_str() : nullptr;
}

SECURITY_MANAGER_API
void security_manager_policy_entries_free(policy_entry *p_entries, const size_t size)
{
    for (size_t i = 0; i < size; i++) {
        delete &p_entries[i];
    }
    delete [] p_entries;
}

SECURITY_MANAGER_API
int security_manager_policy_levels_get(char ***levels, size_t *levels_count)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    if (!levels || !levels_count)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    return try_catch([&] {

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::POLICY_GET_DESCRIPTIONS));

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
                // success - continue
                break;
            case SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY:
                return SECURITY_MANAGER_ERROR_MEMORY;
            case SECURITY_MANAGER_API_ERROR_INPUT_PARAM:
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
            default:
                return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        int count;
        Deserialization::Deserialize(recv, count);
        *levels_count = count;
        LogInfo("Number of policy descriptions: " << *levels_count);

        char **array = new char *[*levels_count];

        for (unsigned int i = 0; i < *levels_count; ++i) {
            std::string level;
            Deserialization::Deserialize(recv, level);

            if (level.empty()) {
                LogError("Unexpected empty level");
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }

            array[i] = strdup(level.c_str());
            if (array[i] == nullptr)
                return SECURITY_MANAGER_ERROR_MEMORY;
        }

        *levels = array;

        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
void security_manager_policy_levels_free(char **levels, size_t levels_count)
{
    for (unsigned int i = 0; i < levels_count; i++)
        free(levels[i]);

    delete[] levels;
}

lib_retcode get_privileges_mapping(const std::string &from_version,
                                   const std::string &to_version,
                                   const std::vector<std::string> &privileges,
                                   char ***privileges_mappings,
                                   size_t *mappings_count)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::GET_PRIVILEGES_MAPPING));
    Serialization::Serialize(send, from_version);
    Serialization::Serialize(send, to_version);
    Serialization::Serialize(send, privileges);

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
            // success - continue
            break;
        case SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY:
            return SECURITY_MANAGER_ERROR_MEMORY;
        case SECURITY_MANAGER_API_ERROR_INPUT_PARAM:
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        default:
            return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    unsigned int count;
    Deserialization::Deserialize(recv, count);
    LogInfo("Number of privilege mappings: " << count);
    size_t i = 0;
    auto free_mapping = std::bind(security_manager_privilege_mapping_free,
                                  std::placeholders::_1, std::ref(i));
    std::unique_ptr<char *[], decltype (free_mapping)> mappings_ptr(new char *[count], free_mapping);

    for (; i < count; ++i) {
        std::string privilege_mapping;
        Deserialization::Deserialize(recv, privilege_mapping);
        if (privilege_mapping.empty()) {
            LogError("Unexpected empty privilege mapping");
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        mappings_ptr.get()[i] = strdup(privilege_mapping.c_str());
        if (mappings_ptr.get()[i] == nullptr)
            return SECURITY_MANAGER_ERROR_MEMORY;
    }

    *privileges_mappings = mappings_ptr.release();
    *mappings_count = count;

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_get_privileges_mapping(const char *from_version,
                                             const char *to_version,
                                             char const * const *privileges,
                                             size_t privileges_count,
                                             char ***privileges_mappings,
                                             size_t *mappings_count)
{
    if (from_version == nullptr || privileges_mappings == nullptr || mappings_count == nullptr) {
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    }
    return try_catch([&] {
        std::vector<std::string> privilegesToMap;
        if (privileges != nullptr) {
            privilegesToMap.reserve(privileges_count);
            privilegesToMap.insert(privilegesToMap.end(), privileges, privileges + privileges_count);
        }
        if (to_version == nullptr)
            to_version = "";
        LogDebug("security_manager_get_privileges_mapping() called with :"
                 " from_version = " << from_version << " to_version = " << to_version <<
                 " privileges_count " << privilegesToMap.size());

        return get_privileges_mapping(from_version, to_version, privilegesToMap,
                                      privileges_mappings, mappings_count);

    });
}
SECURITY_MANAGER_API
void security_manager_privilege_mapping_free(char **privileges_mappings, size_t mappings_count)
{
    for(size_t i = 0; i < mappings_count; i++)
        free(privileges_mappings[i]);
    delete [] privileges_mappings;
}

SECURITY_MANAGER_API
int security_manager_groups_get(char ***groups, size_t *groups_count)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    if (!groups || !groups_count)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    return try_catch([&] {

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::GROUPS_GET));

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
                // success - continue
                break;
            case SECURITY_MANAGER_API_ERROR_OUT_OF_MEMORY:
                return SECURITY_MANAGER_ERROR_MEMORY;
            case SECURITY_MANAGER_API_ERROR_INPUT_PARAM:
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
            default:
                return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        std::vector<std::string> vgroups;
        Deserialization::Deserialize(recv, vgroups);
        const auto vgroups_size = vgroups.size();
        LogInfo("Number of groups: " << vgroups_size);

        std::unique_ptr<char *, std::function<void(char **)>> array(
            static_cast<char **>(calloc(vgroups_size, sizeof(char *))),
            std::bind(security_manager_groups_free, std::placeholders::_1, vgroups_size));

        if (array == nullptr)
            return SECURITY_MANAGER_ERROR_MEMORY;

        for (size_t i = 0; i < vgroups_size; ++i) {
            const auto &group = vgroups.at(i);

            if (group.empty()) {
                LogError("Unexpected empty group");
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }

            array.get()[i] = strdup(group.c_str());
            if (array.get()[i] == nullptr)
                return SECURITY_MANAGER_ERROR_MEMORY;
        }

        *groups_count = vgroups_size;
        *groups = array.release();

        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
void security_manager_groups_free(char **groups, size_t groups_count)
{
    if (groups == nullptr)
        return;

    for (size_t i = 0; i < groups_count; i++)
        free(groups[i]);

    free(groups);
}

static lib_retcode get_app_and_pkg_id_from_smack_label(
        const std::string &label,
        char **pkg_id,
        char **app_id)
{
    std::string appIdString;

    try {
        appIdString = SmackLabels::generateAppNameFromLabel(label);
    } catch (const SmackException::InvalidLabel &) {
        return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
    }

    if (app_id && !(*app_id = strdup(appIdString.c_str()))) {
        LogError("Memory allocation in strdup failed.");
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return pkg_id ? static_cast<lib_retcode>(security_manager_get_app_pkgid(pkg_id, appIdString.c_str()))
            : SECURITY_MANAGER_SUCCESS;
}

static int security_manager_identify_app(
        const std::function<std::string()> &getLabel,
        char **pkg_id,
        char **app_id)
{
    using namespace SecurityManager;

    LogDebug(__PRETTY_FUNCTION__ << " called");

    if (pkg_id == NULL && app_id == NULL) {
        LogError("Both pkg_id and app_id are NULL");
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    }

    std::string label;
    try {
        label = getLabel();
    } catch (...) {
        return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
    }

    return get_app_and_pkg_id_from_smack_label(label, pkg_id, app_id);
}

SECURITY_MANAGER_API
int security_manager_identify_app_from_socket(int sockfd, char **pkg_id, char **app_id)
{
    return try_catch([&] {
        return security_manager_identify_app([&] {
            return SmackLabels::getSmackLabelFromSocket(sockfd);
        }, pkg_id, app_id);
    });
}

SECURITY_MANAGER_API
int security_manager_identify_app_from_pid(pid_t pid, char **pkg_id, char **app_id)
{
    return try_catch([&] {
        return security_manager_identify_app([&] {
            return SmackLabels::getSmackLabelFromPid(pid);
        }, pkg_id, app_id);
    });
}
