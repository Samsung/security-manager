/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 */
/*
 * @file        client-label-monitor.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
 * @version     1.0
 * @brief       Implementation of API for managing list of permited labels for launcher
 */

#include <algorithm>
#include <cstring>
#include <cstdlib>
#include <memory>
#include <string>
#include <string.h>
#include <vector>

#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/smack.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <client-common.h>
#include <config.h>
#include <dpl/log/log.h>
#include <dpl/errno_string.h>
#include <label-monitor.h>
#include <permissible-set.h>
#include <protocols.h>
#include <smack-labels.h>
#include <utils.h>

struct app_labels_monitor {
    int inotify;
    int global_labels_file_watch;
    int user_labels_file_watch;
    bool fresh;
    std::string user_label_file_path;
    std::string global_label_file_path;
    app_labels_monitor() : inotify(-1), global_labels_file_watch(-1), user_labels_file_watch(-1),
                           fresh(true) {}
};

static lib_retcode apply_relabel_list(const std::string &global_label_file,
        const std::string &user_label_file)
{
    std::vector<std::string> appLabels;

    try {
        PermissibleSet::readLabelsFromPermissibleFile(global_label_file, appLabels);
        PermissibleSet::readLabelsFromPermissibleFile(user_label_file, appLabels);
        std::vector<const char*> temp;

        std::transform(appLabels.begin(), appLabels.end(), std::back_inserter(temp),
                [] (std::string &label) {return label.c_str();});

        if (smack_set_relabel_self(temp.data(), temp.size()) != 0) {
            LogError("smack_set_relabel_self failed");
            return SECURITY_MANAGER_ERROR_SET_RELABEL_SELF_FAILED;
        }
    } catch (PermissibleSet::PermissibleSetException::FileOpenError &e) {
        LogWarning("Invalid state of configuration files - smack_set_relabel_self not called");
        return SECURITY_MANAGER_SUCCESS;
    } catch (PermissibleSet::PermissibleSetException::FileReadError &e) {
        LogError("Failed to read the configuration files");
        return SECURITY_MANAGER_ERROR_UNKNOWN;
    }
    return SECURITY_MANAGER_SUCCESS;
}

static lib_retcode inotify_add_watch_full(int fd, const char* pathname, uint32_t mask, int *wd)
{
    int inotify_fd = inotify_add_watch(fd, pathname, mask);
    if (inotify_fd == -1) {
        LogError("Inotify watch failed on file " << pathname << ": " << GetErrnoString(errno));
        return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
    }
    *wd = inotify_fd;
    return SECURITY_MANAGER_SUCCESS;
}

SECURITY_MANAGER_API
int security_manager_app_labels_monitor_init(app_labels_monitor **monitor)
{
    return try_catch([&] {
        LogDebug("security_manager_app_labels_monitor_init() called");
        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }
        int ret;
        lib_retcode ret_lib;

        *monitor = nullptr;

        auto monitorPtr = makeUnique(new app_labels_monitor, security_manager_app_labels_monitor_finish);
        if (!monitorPtr) {
            LogError("Bad memory allocation for app_labels_monitor");
            return SECURITY_MANAGER_ERROR_MEMORY;
        }

        uid_t uid = getuid();
        const std::string globalFile =
            PermissibleSet::getPerrmissibleFileLocation(uid, SM_APP_INSTALL_GLOBAL);
        const std::string userFile =
            PermissibleSet::getPerrmissibleFileLocation(uid, SM_APP_INSTALL_LOCAL);


        ret = inotify_init();
        if (ret == -1) {
            LogError("Inotify init failed: " << GetErrnoString(errno));
            return SECURITY_MANAGER_ERROR_WATCH_ADD_TO_FILE_FAILED;
        }
        monitorPtr.get()->inotify = ret;
        ret_lib = inotify_add_watch_full(monitorPtr->inotify, globalFile.c_str(),
                IN_CLOSE_WRITE, &(monitorPtr->global_labels_file_watch));
        if (ret_lib != SECURITY_MANAGER_SUCCESS) {
            return ret_lib;
        }
        ret_lib = inotify_add_watch_full(monitorPtr->inotify, userFile.c_str(),
                IN_CLOSE_WRITE, &(monitorPtr->user_labels_file_watch));
        if (ret_lib != SECURITY_MANAGER_SUCCESS) {
            return ret_lib;
        }
        monitorPtr->user_label_file_path = userFile;
        monitorPtr->global_label_file_path = globalFile;
        *monitor = monitorPtr.release();
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
void security_manager_app_labels_monitor_finish(app_labels_monitor *monitor)
{
    try_catch([&] {
        LogDebug("security_manager_app_labels_monitor_finish() called");
        if (monitor == nullptr) {
            LogDebug("input param \"monitor\" is nullptr");
            return 0;
        }
        auto monitorPtr = makeUnique(monitor);
        if (monitorPtr->inotify != -1) {
            if (monitorPtr->global_labels_file_watch != -1) {
                int ret = inotify_rm_watch(monitorPtr->inotify, monitorPtr->global_labels_file_watch);
                if (ret == -1) {
                    LogError("Inotify watch removal failed on file " <<
                            Config::APPS_LABELS_FILE << ": " << GetErrnoString(errno));
                }
            }
            if (monitorPtr->user_labels_file_watch != -1) {
                int ret = inotify_rm_watch(monitorPtr->inotify, monitorPtr->user_labels_file_watch);
                if (ret == -1) {
                    LogError("Inotify watch removal failed on file "
                            << monitor->user_label_file_path << ": " << GetErrnoString(errno));
                }
            }
            close(monitorPtr->inotify);
        }
        return 0;
    });
}

SECURITY_MANAGER_API
int security_manager_app_labels_monitor_get_fd(app_labels_monitor const *monitor, int *fd)
{
    return try_catch([&] {
        LogDebug("security_manager_app_labels_monitor_get_fd() called");

        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (fd == nullptr) {
            LogWarning("Error input param \"fd\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (monitor->inotify == -1 || monitor->global_labels_file_watch == -1 ||
            monitor->user_labels_file_watch == -1) {
            LogWarning("Relabel list monitor was not initialized");
            return SECURITY_MANAGER_ERROR_NOT_INITIALIZED;
        }

        *fd = monitor->inotify;
        return SECURITY_MANAGER_SUCCESS;
    });
}

SECURITY_MANAGER_API
int security_manager_app_labels_monitor_process(app_labels_monitor *monitor)
{
    return try_catch([&] {
        LogDebug("security_manager_app_labels_process() called");
        if (monitor == nullptr) {
            LogWarning("Error input param \"monitor\"");
            return SECURITY_MANAGER_ERROR_INPUT_PARAM;
        }

        if (monitor->inotify == -1 || monitor->global_labels_file_watch == -1 ||
            monitor->user_labels_file_watch == -1) {
            LogWarning("Relabel list monitor was not initialized");
            return SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT;
        }

        if (monitor->fresh) {
            monitor->fresh = false;
            return apply_relabel_list(monitor->global_label_file_path,
                   monitor->user_label_file_path);
        }

        int avail;
        int ret = ioctl(monitor->inotify, FIONREAD, &avail);
        if (ret == -1) {
            LogError("Ioctl on inotify descriptor failed: " << GetErrnoString(errno));
            return SECURITY_MANAGER_ERROR_UNKNOWN;
        }

        auto bufPtr = makeUnique<char[]>(avail);
        for (int pos = 0; pos < avail;) {
            int ret = TEMP_FAILURE_RETRY(read(monitor->inotify, bufPtr.get() + pos, avail - pos));
            if (ret == -1) {
                LogError("Inotify read failed: " << GetErrnoString(errno));
                return SECURITY_MANAGER_ERROR_UNKNOWN;
            }
            pos += ret;
        }

        for (int pos = 0; pos < avail;) {
            struct inotify_event event;

            /* Event must be copied to avoid memory alignment issues */
            memcpy(&event, bufPtr.get() + pos, sizeof(struct inotify_event));
            pos += sizeof(struct inotify_event) + event.len;
            if ((event.mask & IN_CLOSE_WRITE) &&
                ((event.wd == monitor->global_labels_file_watch) ||
                 (event.wd == monitor->user_labels_file_watch))
               ){
                lib_retcode r = apply_relabel_list(monitor->global_label_file_path,
                                                   monitor->user_label_file_path);
                if (r != SECURITY_MANAGER_SUCCESS)
                    return r;
                break;
            }
        }
        return SECURITY_MANAGER_SUCCESS;
    });
}



