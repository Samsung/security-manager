/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <cstdlib>
#include <functional>
#include <memory>
#include <unordered_set>
#include <utility>
#include <atomic>
#include <stdlib.h>

#include <unistd.h>
#include <grp.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <sys/smack.h>
#include <sys/capability.h>
#include <sys/syscall.h>
#include <signal.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>
#include <smack-labels.h>
#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <service_impl.h>
#include <connection.h>
#include <check-proper-drop.h>

#include <security-manager.h>
#include <client-offline.h>
#include <dpl/errno_string.h>

#include "filesystem.h"

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

// variables & definitions for thread security attributes
static std::string g_app_label;
static std::atomic<int> g_threads_count;
static std::map<uid_t, std::string> g_tid_attr_current_map;
static bool g_smack_fs_path;
static cap_t g_cap;
#define MAX_SIG_WAIT_TIME   1000

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
int security_manager_app_inst_req_set_target_version(app_inst_req *p_req, const char *tizen_ver)
{
    if (!p_req || !tizen_ver)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->tizenVersion = tizen_ver;

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_set_author_id(app_inst_req *p_req, const char *author_name)
{
    if (!p_req || !author_name || strlen(author_name) == 0)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->authorName.assign(author_name);
    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_set_app_id(app_inst_req *p_req, const char *app_name)
{
    if (!p_req || !app_name)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->appName = app_name;

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_set_pkg_id(app_inst_req *p_req, const char *pkg_name)
{
    if (!p_req || !pkg_name)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->pkgName = pkg_name;

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

    p_req->pkgPaths.push_back(std::make_pair(path, path_type));

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_inst_req_set_install_type(app_inst_req *p_req, const enum app_install_type type)
{
    if (!p_req || (type <= SM_APP_INSTALL_NONE) || (type >= SM_APP_INSTALL_END))
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->installationType = static_cast<int>(type);

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_install(const app_inst_req *p_req)
{
    using namespace SecurityManager;

    return try_catch([&]() -> int {
        //checking parameters
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->appName.empty() || p_req->pkgName.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        int retval;
        ClientOffline offlineMode;
        if (offlineMode.isOffline()) {
            Credentials creds = offlineMode.getCredentials();
            retval = SecurityManager::ServiceImpl().appInstall(creds, app_inst_req(*p_req));
        } else {
            MessageBuffer send, recv;

            //put data into buffer
            Serialization::Serialize(send,
                                     (int)SecurityModuleCall::APP_INSTALL,
                                     p_req->appName,
                                     p_req->pkgName,
                                     p_req->privileges,
                                     p_req->pkgPaths,
                                     p_req->uid,
                                     p_req->tizenVersion,
                                     p_req->authorName,
                                     p_req->installationType);

            //send buffer to server
            retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
            if (retval != SECURITY_MANAGER_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << retval);
                return retval;
            }

            //receive response from server
            Deserialization::Deserialize(recv, retval);
        }
        return retval;
    });
}

SECURITY_MANAGER_API
int security_manager_app_uninstall(const app_inst_req *p_req)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;

    return try_catch([&]() -> int {
        //checking parameters
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->appName.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        //put data into buffer
        Serialization::Serialize(send, (int)SecurityModuleCall::APP_UNINSTALL,
            p_req->appName,
            p_req->pkgName,
            p_req->privileges,
            p_req->pkgPaths,
            p_req->uid,
            p_req->tizenVersion,
            p_req->authorName,
            p_req->installationType);

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        return retval;
    });
}

SECURITY_MANAGER_API
int security_manager_get_app_pkgid(char **pkg_name, const char *app_name)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;

    LogDebug("security_manager_get_app_pkgid() called");

    return try_catch([&]() -> int {
        //checking parameters

        if (app_name == NULL) {
            LogError("security_manager_app_get_pkgid: app_name is NULL");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (pkg_name == NULL) {
            LogError("security_manager_app_get_pkgid: pkg_name is NULL");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_GET_PKG_NAME),
            std::string(app_name));

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogDebug("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        if (retval != SECURITY_MANAGER_SUCCESS)
            return retval;

        std::string pkgNameString;
        Deserialization::Deserialize(recv, pkgNameString);
        if (pkgNameString.empty()) {
            LogError("Unexpected empty pkgName");
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        *pkg_name = strdup(pkgNameString.c_str());
        if (*pkg_name == NULL) {
            LogError("Failed to allocate memory for pkgName");
            return SECURITY_MANAGER_ERROR_MEMORY;
        }

        return SECURITY_MANAGER_SUCCESS;
    });
}

static int setup_smack(const char *label)
{
    /* Here we also should change open socket labels for future process identification.
       However, since Smack support for "dyntransition"-like feature will be enabled soon,
       relabeling the sockets will no longer be possible.

       After careful review it was found that only opened sockets are ones to systemd
       (user and system session) and enlightment. Both services are not integrated with Cynara
       and seem to be fine with these sockets retaining IPIN/IPOUT "User" label.
    */
    // Set Smack label of current process
    if (smack_set_label_for_self(label) != 0) {
        LogError("Failed to set Smack label for application: " << label);
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_set_process_label_from_appid(const char *app_name)
{
    int ret;
    std::string appLabel;

    LogDebug("security_manager_set_process_label_from_appid() called");

    if (smack_smackfs_path() == NULL)
        return SECURITY_MANAGER_SUCCESS;

    try {
        appLabel = SecurityManager::SmackLabels::generateAppLabel(app_name);
    } catch (...) {
        LogError("Failed to generate smack label for appName: " << app_name);
        return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
    }

    if ((ret = setup_smack(appLabel.c_str())) != SECURITY_MANAGER_SUCCESS) {
        LogError("Failed to set smack label " << appLabel << " for current process");
        return ret;
    }

    return SECURITY_MANAGER_SUCCESS;
}

static int getProcessGroups(std::vector<gid_t> &groups)
{
    int ret = getgroups(0, nullptr);
    if (ret == -1) {
        LogError("Unable to get number of current supplementary groups: " <<
            GetErrnoString(errno));
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    int cnt = ret;

    std::unique_ptr<gid_t[]> groupsPtr(new gid_t[cnt]);
    if (!groupsPtr) {
        LogError("Memory allocation failed.");
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    ret = getgroups(cnt, groupsPtr.get());
    if (ret == -1) {
        LogError("Unable to get list of current supplementary groups: " <<
            GetErrnoString(errno));
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    groups.assign(groupsPtr.get(), groupsPtr.get() + cnt);
    return SECURITY_MANAGER_SUCCESS;
}

static int setProcessGroups(const std::vector<gid_t> &groups)
{
    int ret = setgroups(groups.size(), groups.data());
    if (ret == -1) {
        LogError("Unable to set list of current supplementary groups: " <<
            GetErrnoString(errno));
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    return SECURITY_MANAGER_SUCCESS;
}

static int groupNamesToGids(const std::vector<std::string> &groupNames,
    std::vector<gid_t> &groups)
{
    groups.reserve(groupNames.size());
    for (const auto &groupName : groupNames) {
        struct group *grp = getgrnam(groupName.c_str());
        if (grp == nullptr) {
            LogError("No such group: " << groupName);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }
        groups.push_back(grp->gr_gid);
    }

    return SECURITY_MANAGER_SUCCESS;
}

static int getPrivilegedGroups(std::vector<gid_t> &groups)
{
    MessageBuffer send, recv;
    int ret;

    Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::GROUPS_GET));
    ret = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
    if (ret != SECURITY_MANAGER_SUCCESS) {
        LogDebug("Error in sendToServer. Error code: " << ret);
        return ret;
    }

    Deserialization::Deserialize(recv, ret);
    if (ret != SECURITY_MANAGER_SUCCESS) {
        LogError("Failed to get list of groups from security-manager service. " <<
            "Error code: " << ret);
        return ret;
    }

    std::vector<std::string> groupNames;
    Deserialization::Deserialize(recv, groupNames);
    return groupNamesToGids(groupNames, groups);
}

static int getAppGroups(const std::string appName, std::vector<gid_t> &groups)
{
    MessageBuffer send, recv;
    int ret;

    Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_GET_GROUPS), appName);
    ret = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
    if (ret != SECURITY_MANAGER_SUCCESS) {
        LogDebug("Error in sendToServer. Error code: " << ret);
        return ret;
    }

    Deserialization::Deserialize(recv, ret);
    if (ret != SECURITY_MANAGER_SUCCESS) {
        LogError("Failed to get list of groups from security-manager service. " <<
            "Error code: " << ret);
        return ret;
    }

    std::vector<std::string> groupNames;
    Deserialization::Deserialize(recv, groupNames);
    return groupNamesToGids(groupNames, groups);
}

inline static uid_t gettid()
{
    return syscall(SYS_gettid);
}

inline static void tkill(uid_t tid)
{
    syscall(SYS_tkill, tid, SIGUSR1);
}

inline static int label_for_self_internal()
{
    int fd;
    int ret;
    fd = open(g_tid_attr_current_map[gettid()].c_str(), O_WRONLY);
    if (fd < 0) {
        return -1;
    }
    ret = write(fd, g_app_label.c_str(), g_app_label.length());
    close(fd);

    if (ret < 0) {
        return -1;
    }
    return 0;
}

static inline int security_manager_sync_threads_internal(const char *app_name)
{
    LogDebug("security_manager_sync_threads_internal called for app_name: " << app_name);

    if (ATOMIC_INT_LOCK_FREE != 2) {
        LogError("std::atomic<int> is not always lock free");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    FS::FileNameVector files = FS::getDirsFromDirectory("/proc/self/task");
    uid_t cur_tid = gettid();

    g_app_label = SecurityManager::SmackLabels::generateAppLabel(app_name);
    g_threads_count = 0;
    g_tid_attr_current_map.clear();
    g_smack_fs_path = smack_smackfs_path() != NULL;
    g_cap = cap_init();

    if (!g_cap) {
        LogError("Unable to allocate capability object");
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    if (cap_clear(g_cap)) {
        LogError("Unable to initialize capability object");
        cap_free(g_cap);
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    std::atomic_thread_fence(std::memory_order_release);

    struct sigaction act;
    struct sigaction old;
    memset(&act, '\0', sizeof(act));
    memset(&old, '\0', sizeof(old));

    sigemptyset(&act.sa_mask);
    act.sa_flags = SA_RESTART;
    act.sa_handler = [](int signo) {
        (void)signo;

        std::atomic_thread_fence(std::memory_order_acquire);

        if (g_smack_fs_path)
            if(label_for_self_internal() != 0)
                return;

        if (cap_set_proc(g_cap))
            return;

        g_threads_count++;
    };

    if (sigaction(SIGUSR1, &act, &old) < 0) {
        LogError("Error in sigaction()");
        cap_free(g_cap);
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    int sent_signals_count = 0;

    for (auto const &e : files) {
        if (e.compare(".") == 0 || e.compare("..") == 0)
            continue;

        int tid = atoi(e.c_str());
        if (tid == static_cast<int>(cur_tid))
            continue;

        g_tid_attr_current_map[tid] = "/proc/self/task/" + std::to_string(tid) + "/attr/current";
        sent_signals_count++;
        tkill(tid);
    }

    LogDebug("sent_signals_count: " << sent_signals_count);

    for (int i = 0; g_threads_count != sent_signals_count && i < MAX_SIG_WAIT_TIME; ++i)
        usleep(1000);   // 1 ms

    sigaction(SIGUSR1, &old, nullptr);

    if (g_threads_count != sent_signals_count) {
        LogError("Not all threads synchronized: threads done: " << g_threads_count);
        cap_free(g_cap);
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    if (g_smack_fs_path)
        if (smack_set_label_for_self(g_app_label.c_str()) != 0) {
            LogError("smack_set_label_for_self failed");
            cap_free(g_cap);
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

    if (cap_set_proc(g_cap)) {
        LogError("Can't drop main thread capabilities");
        cap_free(g_cap);
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }

    cap_free(g_cap);

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_set_process_groups_from_appid(const char *app_name)
{
    using namespace SecurityManager;
    int ret;

    LogDebug("security_manager_set_process_groups_from_appid() called");

    return try_catch([&]() -> int {
        //checking parameters

        if (app_name == nullptr) {
            LogError("app_name is NULL");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        std::vector<gid_t> currentGroups;
        ret = getProcessGroups(currentGroups);
        if (ret != SECURITY_MANAGER_SUCCESS)
            return ret;
        LogDebug("Current supplementary groups count: " << currentGroups.size());

        std::vector<gid_t> privilegedGroups;
        ret = getPrivilegedGroups(privilegedGroups);
        if (ret != SECURITY_MANAGER_SUCCESS)
            return ret;
        LogDebug("All privileged supplementary groups count: " << privilegedGroups.size());

        std::vector<gid_t> allowedGroups;
        ret = getAppGroups(app_name, allowedGroups);
        if (ret != SECURITY_MANAGER_SUCCESS)
            return ret;
        LogDebug("Allowed privileged supplementary groups count: " << allowedGroups.size());

        std::unordered_set<gid_t> groupsSet(currentGroups.begin(), currentGroups.end());
        // Remove all groups that are mapped to privileges, so if app is not granted
        // the privilege, the group will be dropped from current process
        for (gid_t group : privilegedGroups)
            groupsSet.erase(group);

        // Re-add those privileged groups that an app is entitled to
        groupsSet.insert(allowedGroups.begin(), allowedGroups.end());
        LogDebug("Final supplementary groups count: " << groupsSet.size());

        return setProcessGroups(std::vector<gid_t>(groupsSet.begin(), groupsSet.end()));
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
int security_manager_prepare_app(const char *app_name)
{
    return try_catch([&] {
        LogDebug("security_manager_prepare_app() called");
        int ret;

        ret = security_manager_set_process_groups_from_appid(app_name);
        if (ret != SECURITY_MANAGER_SUCCESS) {
            LogWarning("Unable to setup process groups for application. Privileges with direct access to resources will not work.");
        }

        ret = security_manager_sync_threads_internal(app_name);
        if (ret != SECURITY_MANAGER_SUCCESS) {
            LogError("Can't properly setup application threads (Smack label & capabilities)");
            exit(EXIT_FAILURE);
        }

        try {
            CheckProperDrop cpd;
            cpd.getThreads();
            if (!cpd.checkThreads()) {
                LogError("Privileges haven't been properly dropped for the whole process");
                exit(EXIT_FAILURE);
            }
        } catch (const SecurityManager::Exception &e) {
            LogError("Error while checking privileges of the process: " << e.DumpToString());
            exit(EXIT_FAILURE);
        }

        return ret;
    });
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
            Credentials creds = offlineMode.getCredentials();
            retval = SecurityManager::ServiceImpl().userAdd(creds, p_req->uid, p_req->utype);
        } else {
            MessageBuffer send, recv;
            //server is working

            //put data into buffer
            Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::USER_ADD),
                p_req->uid, p_req->utype);

            //send buffer to server
            retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
            if (retval != SECURITY_MANAGER_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << retval);
                return retval;
            }

            //receive response from server
            Deserialization::Deserialize(recv, retval);
        }
        return retval;
    });
}

SECURITY_MANAGER_API
int security_manager_user_delete(const user_req *p_req)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    if (!p_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    return try_catch([&]() -> int {

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::USER_DELETE),
            p_req->uid);

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        return retval;
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
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);
        return retval;
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

    return try_catch([&]() -> int {
        //put request into buffer
        Serialization::Serialize(send, static_cast<int>(call_type),
            *p_filter);

        //send it to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }
        //receive response from server
        Deserialization::Deserialize(recv, retval);
        switch (retval) {
            default:
                return retval;
            case SECURITY_MANAGER_SUCCESS: {
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
int security_manager_policy_entry_set_application(policy_entry *p_entry, const char *app_name)
{
    if (!p_entry)
        return  SECURITY_MANAGER_ERROR_INPUT_PARAM;
    p_entry->appName = app_name;
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
    return p_entry ? p_entry->appName.c_str() : nullptr;
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
    return try_catch([&]() -> int {

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::POLICY_GET_DESCRIPTIONS));

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);

        if (retval != SECURITY_MANAGER_SUCCESS) {
            return retval;
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

SECURITY_MANAGER_API
int security_manager_groups_get(char ***groups, size_t *groups_count)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    if (!groups || !groups_count)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    return try_catch([&]() -> int {

        //put data into buffer
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::GROUPS_GET));

        //send buffer to server
        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        //receive response from server
        Deserialization::Deserialize(recv, retval);

        if (retval != SECURITY_MANAGER_SUCCESS) {
            return retval;
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
        char **pkg_name,
        char **app_name)
{
    std::string appNameString;

    try {
        appNameString = SmackLabels::generateAppNameFromLabel(label);
    } catch (const SmackException::InvalidLabel &) {
        return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
    }

    if (app_name && !(*app_name = strdup(appNameString.c_str()))) {
        LogError("Memory allocation in strdup failed.");
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return pkg_name ? static_cast<lib_retcode>(security_manager_get_app_pkgid(pkg_name, appNameString.c_str()))
            : SECURITY_MANAGER_SUCCESS;
}

static int security_manager_identify_app(
        const std::function<std::string()> &getLabel,
        char **pkg_name,
        char **app_name)
{
    using namespace SecurityManager;

    LogDebug(__PRETTY_FUNCTION__ << " called");

    if (pkg_name == NULL && app_name == NULL) {
        LogError("Both pkg_name and app_name are NULL");
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    }

    std::string label;
    try {
        label = getLabel();
    } catch (...) {
        return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
    }

    return get_app_and_pkg_id_from_smack_label(label, pkg_name, app_name);
}

SECURITY_MANAGER_API
int security_manager_identify_app_from_socket(int sockfd, char **pkg_name, char **app_name)
{
    return try_catch([&] {
        return security_manager_identify_app([&] {
            return SmackLabels::getSmackLabelFromSocket(sockfd);
        }, pkg_name, app_name);
    });
}

SECURITY_MANAGER_API
int security_manager_identify_app_from_pid(pid_t pid, char **pkg_name, char **app_name)
{
    return try_catch([&] {
        return security_manager_identify_app([&] {
            return SmackLabels::getSmackLabelFromPid(pid);
        }, pkg_name, app_name);
    });
}

SECURITY_MANAGER_API
int security_manager_app_has_privilege(const char *app_name, const char *privilege,
                                       uid_t uid, int *result)
{
    using namespace SecurityManager;
    MessageBuffer send, recv;
    return try_catch([&]() -> int {
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_HAS_PRIVILEGE),
            std::string(app_name), std::string(privilege), uid);

        int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
        if (retval != SECURITY_MANAGER_SUCCESS) {
            LogError("Error in sendToServer. Error code: " << retval);
            return retval;
        }

        Deserialization::Deserialize(recv, retval);

        if (retval != SECURITY_MANAGER_SUCCESS) {
            return retval;
        }

        Deserialization::Deserialize(recv, *result);
        LogDebug("app_has_privilege result: " << *result);

        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_private_sharing_req_new(private_sharing_req **pp_req)
{
    if (!pp_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    try {
        *pp_req = new private_sharing_req;
    } catch (std::bad_alloc& ex) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    }

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
void security_manager_private_sharing_req_free(private_sharing_req *p_req)
{
    delete p_req;
}

SECURITY_MANAGER_API
int security_manager_private_sharing_req_set_owner_appid(
    private_sharing_req *p_req, const char *app_name)
{
    return try_catch([&] {
        if (!p_req || !app_name)
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        p_req->ownerAppName = app_name;
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_private_sharing_req_set_target_appid(
    private_sharing_req *p_req, const char *app_name)
{
    return try_catch([&] {
        if (!p_req || !app_name)
                return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        p_req->targetAppName = app_name;
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_private_sharing_req_add_paths(private_sharing_req *p_req,
                                                   const char **pp_paths,
                                                   size_t path_count)
{
    return try_catch([&] {
        if (!p_req || !pp_paths)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        for (size_t i = 0; i < path_count; i++) {
            p_req->paths.push_back(pp_paths[i]);
        }
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_private_sharing_apply(const private_sharing_req *p_req)
{
    using namespace SecurityManager;
    return try_catch([&]() -> int {
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->ownerAppName.empty() || p_req->targetAppName.empty() || p_req->paths.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_APPLY_PRIVATE_SHARING));
        Serialization::Serialize(send, p_req->ownerAppName);
        Serialization::Serialize(send, p_req->targetAppName);
        Serialization::Serialize(send, p_req->paths);

        //send buffer to server
       int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
       if (retval != SECURITY_MANAGER_SUCCESS) {
           LogError("Error in sendToServer. Error code: " << retval);
           return retval;
       }

       //receive response from server
       Deserialization::Deserialize(recv, retval);
       return retval;
    });
}

SECURITY_MANAGER_API
int security_manager_private_sharing_drop(const private_sharing_req *p_req)
{
    using namespace SecurityManager;
    return try_catch([&]() -> int {
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->ownerAppName.empty() || p_req->targetAppName.empty() || p_req->paths.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        MessageBuffer send, recv;
        Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::APP_DROP_PRIVATE_SHARING));
        Serialization::Serialize(send, p_req->ownerAppName);
        Serialization::Serialize(send, p_req->targetAppName);
        Serialization::Serialize(send, p_req->paths);

        //send buffer to server
       int retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
       if (retval != SECURITY_MANAGER_SUCCESS) {
           LogError("Error in sendToServer. Error code: " << retval);
           return retval;
       }

       //receive response from server
       Deserialization::Deserialize(recv, retval);
       return retval;
    });
}

/***************************PATHS***************************************/

SECURITY_MANAGER_API
int security_manager_path_req_new(path_req **pp_req)
{
    if (!pp_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    try {
        *pp_req = new path_req;
    } catch (const std::bad_alloc&) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    }
    (*pp_req)->uid = geteuid();

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
void security_manager_path_req_free(path_req *p_req)
{
    delete p_req;
}

SECURITY_MANAGER_API
int security_manager_path_req_set_pkg_id(path_req *p_req, const char *pkg_id)
{
    if (!p_req || !pkg_id)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    try {
        p_req->pkgName.assign(pkg_id);
    } catch (const std::bad_alloc&) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::length_error&) {
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    }
    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_path_req_set_install_type(path_req *p_req, const enum app_install_type type)
{
    if (!p_req || (type <= SM_APP_INSTALL_NONE) || (type >= SM_APP_INSTALL_END))
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->installationType = static_cast<int>(type);

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_path_req_add_path(path_req *p_req, const char *path, const int path_type)
{
    if (!p_req || !path || (path_type < 0) || (path_type >= SECURITY_MANAGER_ENUM_END))
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    try {
        p_req->pkgPaths.push_back(std::make_pair(path, path_type));
    } catch (const std::bad_alloc&) {
        return SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::length_error&) {
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;
    }

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_path_req_set_uid(path_req *p_req, const uid_t uid)
{
    if (!p_req)
        return SECURITY_MANAGER_ERROR_INPUT_PARAM;

    p_req->uid = uid;

    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_paths_register(const path_req *p_req)
{
    using namespace SecurityManager;

    return try_catch([&]() -> int {
        //checking parameters
        if (!p_req)
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        if (p_req->pkgName.empty())
            return SECURITY_MANAGER_ERROR_REQ_NOT_COMPLETE;

        int retval;
        ClientOffline offlineMode;
        if (offlineMode.isOffline()) {
            Credentials creds = offlineMode.getCredentials();
            retval = SecurityManager::ServiceImpl().pathsRegister(creds, *p_req);
        } else {
            MessageBuffer send, recv;

            //put data into buffer
            Serialization::Serialize(send,
                                     (int)SecurityModuleCall::PATHS_REGISTER,
                                     p_req->pkgName,
                                     p_req->uid,
                                     p_req->pkgPaths,
                                     p_req->installationType);

            //send buffer to server
            retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
            if (retval != SECURITY_MANAGER_SUCCESS) {
                LogError("Error in sendToServer. Error code: " << retval);
                return retval;
            }

            //receive response from server
            Deserialization::Deserialize(recv, retval);
        }
        return retval;
    });
}
