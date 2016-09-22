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
 * @file        label-monitor.h
 * @author      Rafal Krypa (r.krypa@samsung.com)
 * @author      Radoslaw Bartosiak (r.bartosiak@samsung.com)
 * @version     1.0
 * @brief       Header with API targeted for launcher to monitor labels of installed applications
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "security-manager-types.h"

typedef struct app_labels_monitor app_labels_monitor;

/**
 * Initialize applications' labels monitor
 * The monitor is intended for watching for changes to the list of labels
 * assigned to currently installed applications.
 * It will allocate resources that must be freed later by
 * \ref security_manager_app_labels_monitor_finish.
 * Intended user of this function is the application launcher.
 *
 * \param[out]  monitor            pointer to the resulting applications' label monitor
 *
 * \return SECURITY_MANAGER_SUCCESS on success or error code on failure
 *
 * \par Example
 * \parblock
 * (warning: simplified code example, with committed error handling)
 * \code{.c}
 *     app_labels_monitor *monitor;
 *     int fd;
 *     nfds_t nfds = 1;
 *     struct pollfd fds[1];
 *
 *     security_manager_app_labels_monitor_init(&monitor);
 *     security_manager_app_labels_monitor_process(monitor);
 *     security_manager_app_labels_monitor_get_fd(monitor, &fd);
 *     fds[0].fd = fd;
 *     fds[0].events = POLLIN;
 *     while (1) {
 *         int poll_num = TEMP_FAILURE_RETRY(poll(fds, nfds, -1));
 *         if (poll_num > 0) {
 *             if (fds[0].revents & POLLIN) {
 *                 security_manager_app_labels_monitor_process(monitor);
 *                 // Do your stuff - react on new list of applications' labels
 *             }
 *         }
 *     }
 *     // ...
 *     // Before finishing, release the labels monitor
 *     security_manager_app_labels_monitor_finish(monitor);
 *
 * \endcode
 * \endparblock
 */
int security_manager_app_labels_monitor_init(app_labels_monitor **monitor);

/**
 * De-initialize applications' labels monitor
 * Frees all resources previously allocated by \ref security_manager_app_labels_monitor_init
 *
 * \param[in]  monitor             an initialized applications' label monitor
 *
 * \return SECURITY_MANAGER_SUCCESS on success or error code on failure
 */
void security_manager_app_labels_monitor_finish(app_labels_monitor *monitor);

/**
 * Retrieve file descriptor for waiting on applications' labels monitor
 * The file descriptor should be put to a select-like waiting loop. It will indicate
 * new list of applications' labels by being ready for reading.
 *
 * \param[in]  monitor             an initialized applications' label monitor
 * \param[out] fd                  pointer to the resulting file descriptor
 *
 * \return SECURITY_MANAGER_SUCCESS on success or error code on failure
 */
int security_manager_app_labels_monitor_get_fd(app_labels_monitor const *monitor, int *fd);

/**
 * Apply new list of applications' labels to Smack relabel-list of the current process
 * This will give permission to the current process to change its Smack label to one
 * of application labels, even after it drops CAP_MAC_ADMIN capability.
 *
 * \param[in]  monitor             an initialized applications' label monitor
 *
 * \return SECURITY_MANAGER_SUCCESS on success or error code on failure
 *
 * Access to this function requires CAP_MAC_ADMIN capability.
 */
int security_manager_app_labels_monitor_process(app_labels_monitor *monitor);

#ifdef __cplusplus
}
#endif
