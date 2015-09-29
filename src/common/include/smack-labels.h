/*
 *  Copyright (c) 2014-2015 Samsung Electronics Co., Ltd All Rights Reserved
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
#ifndef _SMACK_LABELS_H_
#define _SMACK_LABELS_H_

#include <string>
#include <utility>
#include <smack-exceptions.h>
#include <security-manager.h>

namespace SecurityManager {
namespace SmackLabels {

/**
 * Sets Smack labels on a directory and its contents, recursively.
 *
 * @param pkgId[in] application's package identifier
 * @param path[in] path to a file or directory to setup
 * @param pathType[in] type of path to setup. See description of
 *         app_install_path_type in security-manager.h for details
 * @param zoneId[in] ID of zone for which label should be set
 */
void setupPath(const std::string &pkgId, const std::string &path,
    app_install_path_type pathType, const std::string &zoneId);

/**
 * Sets Smack labels on a <ROOT_APP>/<pkg_id> non-recursively
 *
 * @param pkgId[in] package identifier
 * @param basePath[in] <ROOT_APP> path
 */
void setupAppBasePath(const std::string &pkgId, const std::string &basePath);

/**
 * Generates application name for a label fetched from Cynara
 *
 * @param[in] label string to fetch application name for
 * @return application name on success, empty string on error.
*/
std::string generateAppNameFromLabel(const std::string &label);

/**
 * Generates label for an application with an application ID read from @ref appId.
 *
 * @param[in] appId application's identifier
 * @return resulting Smack label
*/
std::string generateAppLabel(const std::string &appId);

/**
 * Generates label for an application with a package ID read from @ref pkgId.
 *
 * @param[in] pkgId
 * @return resulting Smack label
 */
std::string generatePkgLabel(const std::string &pkgId);

/**
 * Generates label for private application RO files with package ID @ref pkgId
 *
 * @param[in] pkgId
 * @return resulting Smack label
 */
std::string generatePkgROLabel(const std::string &pkgId);

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

} // namespace SmackLabels
} // namespace SecurityManager

#endif /* _SMACK_LABELS_H_ */
