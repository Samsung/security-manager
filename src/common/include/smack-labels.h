/*
 *  Copyright (c) 2014-2016 Samsung Electronics Co., Ltd All Rights Reserved
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
/**
 * @file        smack-labels.h
 * @author      Jan Cybulski <j.cybulski@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Header file of functions managing smack labels
 *
 */
#pragma once

#include <string>
#include <utility>
#include <smack-exceptions.h>
#include <security-manager.h>

namespace SecurityManager {
namespace SmackLabels {

/**
 * Sets Smack labels on a directory and its contents, recursively.
 *
 * @param pkgName[in] application's package identifier
 * @param path[in] path to a file or directory to setup
 * @param pathType[in] type of path to setup. See description of
 *         app_install_path_type in security-manager.h for details
 */
void setupPath(
        const std::string &pkgName,
        const std::string &path,
        app_install_path_type pathType,
        const int authorId = -1);

/**
 * Sets Smack labels on a <ROOT_APP>/<pkg_id> non-recursively
 *
 * @param basePath[in] <ROOT_APP>/<pkg_id> path
 */
void setupPkgBasePath(const std::string &basePath);

/**
 * Changes Smack label on path to enable private sharing
 *
 * @param pkgName[in] package identifier
 * @param path[in] path
 */
void setupSharedPrivatePath(const std::string &pkgName, const std::string &path);

/**
 * Generates application name for a label fetched from Cynara
 *
 * @param[in] label string to fetch application name for
 * @param[out] appName application identifier (can be empty if label belongs to non-hybrid app)
 * @param[out] pkgName package identifier (cannot be empty)
 * @return application name on success, empty string on error.
*/
void generateAppPkgNameFromLabel(const std::string &label, std::string &appName, std::string &pkgName);

/**
 * Generates label for an application identifier
 *
 * @param[in] appName application identifier
 * @param[in] pkgName package identifier
 * @param[in] isHybrid package is hybrid flag
 * @return resulting Smack label
*/
std::string generateProcessLabel(const std::string &appName,
                                 const std::string &pkgName,
                                 bool isHybrid);

/**
 * Generates label for an application with @ref pkgName, specific
 * for folders that can be modified by owner and other apps can only read it.
 *
 * @param[in] pkgName application package identifier
 * @return resulting Smack label
*/
std::string generatePathSharedROLabel(const std::string &pkgName);

/**
 * Generates label for a package identifier
 *
 * @param[in] pkgName package identifier
 * @return resulting Smack label
 */
std::string generatePathRWLabel(const std::string &pkgName);

/**
 * Generates label for private application RO files with package identifier @ref pkgName
 *
 * @param[in] pkgName package identifier
 * @return resulting Smack label
 */
std::string generatePathROLabel(const std::string &pkgName);

/**
 * Generates unique label per path for private path sharing.
 *
 * @param[in] pkgName
 * @param[in] path
 * @return resulting Smack label
 */
std::string generateSharedPrivateLabel(const std::string &pkgName, const std::string &path);

/*
 * Generates label for trusted paths. Trusted paths are paths where all application
 * of the same author have rw rights.
 *
 * @param[in] authorId
 * @return resulting Smack label
 */
std::string generatePathTrustedLabel(const int authorId);

/**
 * Returns smack label for given socket
 *
 * @param[in] socket descriptor
 * @return resulting Smack label
 */
std::string getSmackLabelFromSocket(int socketFd);

/**
 * Returns smack label for given process
 *
 * @param[in] process identifier
 * @return resulting Smack label
 */
std::string getSmackLabelFromPid(pid_t pid);

/**
 * Returns smack label for given path
 *
 * @param[in] process identifier
 * @return resulting Smack label
 */
std::string getSmackLabelFromPath(const std::string &path);

/**
 * Returns smack label for current process
 *
 * @param[in] sock socket file descriptor
 * @return resulting Smack label
 */
std::string getSmackLabelFromSelf(void);

} // namespace SmackLabels
} // namespace SecurityManager
