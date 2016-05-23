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
 * @file        sharing_info.h
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Definitions of sharing info wrapping types.
 */

#ifndef SECURITY_MANAGER_SHARING_INFO
#define SECURITY_MANAGER_SHARING_INFO

namespace SecurityManager {
class AppInfo {
    std::string name;
    bool isInstalled;
    bool operator<(const AppInfo &lhs, const AppInfo &rhs) {
        return lhs.name < rhs.name;
    }
};

typedef std::vector<std::string> PathLabelVector;
typedef std::map<AppInfo, PathLabelVector> OwnerSharingInfo;

} //namespace SecurityManager

#endif // SECURITY_MANAGER_SHARING_INFO
