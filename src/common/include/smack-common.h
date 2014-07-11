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
 */
/*
 * @file        smack-common.h
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @author      Jan Cybulski <j.cybulski@samsung.com>
 * @version     1.0
 * @brief       Header file for smack-related functions and constants
 */
#ifndef _SMACK_COMMON_H_
#define _SMACK_COMMON_H_

#include <string>
#include <linux/xattr.h>

namespace SecurityManager {
    /* Const defined below is used to label links to executables */
    const char *const XATTR_NAME_TIZENEXEC =  XATTR_SECURITY_PREFIX "TIZEN_EXEC_LABEL";

    /**
     * Generates label for application with package identifier
     * read from @ref pkgId and assigns it to @ref label.
     *
     * @param[in] pkgId application's package identifier
     * @param[out] label string in which application's label will be stored
     * @return true on success, false on error.
    */
    bool generateAppLabel(const std::string &pkgId, std::string &label);
}

#endif /* _SMACK_COMMON_H_ */

