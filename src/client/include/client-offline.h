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
 * @file        client-common.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Helper class for client "off-line" mode detection
 */

#ifndef _SECURITY_MANAGER_OFFLINE_
#define _SECURITY_MANAGER_OFFLINE_

#include <file-lock.h>

namespace SecurityManager {

class ClientOffline {
public:
    ClientOffline();
    ~ClientOffline();
    bool isOffline(void);

private:
    bool offlineMode;
    SecurityManager::FileLocker *serviceLock;
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_OFFLINE_
