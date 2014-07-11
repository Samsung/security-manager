/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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

#include "security-manager.h"

namespace SecurityManager {

/**
 * Generates label for application with package identifier
 * read from @ref pkgId and assigns it to @ref label.
 * @param[in] pkgId application's package identifier.
 * @param[out] label string into which application's label will be stored into.
 *
 * @return true on success, false on error.
*/
bool generateAppLabel(const std::string &pkgId, std::string &label);

/**
 * Sets Smack labels on a directory and its contents, recursively.
 *
 * @param pkgId[in] application's package identifier
 * @param path[in] path to a file or directory to setup
 * @param pathType[in] type of path to setup. See description of
 *         app_install_path_type in security-manager.h for details
 *
 * @return true on success, false on error.
 */
bool setupPath(const std::string &pkgId, const std::string &path,
    app_install_path_type pathType);

} // namespace SecurityManager

#endif /* _SMACK_LABELS_H_ */
