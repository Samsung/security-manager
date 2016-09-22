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
 */
/*
 * @file        client-offline.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Helper class for client "off-line" mode detection
 */

#pragma once

#include <credentials.h>
#include <file-lock.h>

namespace SecurityManager {

class ClientOffline {
public:
    ClientOffline(bool wakeUp = true);
    ~ClientOffline();
    ClientOffline& operator=(const ClientOffline &) = delete;
    bool isOffline(void);
    Credentials getCredentials();
private:
    bool m_offlineMode;
    SecurityManager::FileLocker *m_serviceLock;
};

} // namespace SecurityManager
