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
 * @file        client-offline.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Helper class for client "off-line" mode detection
 */

#include <client-common.h>
#include <client-offline.h>
#include <client-request.h>
#include <dpl/log/log.h>

namespace SecurityManager {

ClientOffline::ClientOffline(bool wakeUp)
  : m_offlineMode(false)
  , m_serviceLock(nullptr)
{
    if (geteuid()) {
        LogInfo("UID != 0, attempting only on-line mode.");
        return;
    }

    try {
        m_serviceLock = new SecurityManager::FileLocker(SecurityManager::SERVICE_LOCK_FILE, false);
        if (wakeUp && m_serviceLock->Locked()) {
            LogInfo("Service isn't running, try to trigger it via socket activation.");
            m_serviceLock->Unlock();
            if (ClientRequest(SecurityModuleCall::NOOP).send().failed()) {
                LogInfo("Socket activation attempt failed.");
                m_serviceLock->Lock();
                m_offlineMode = m_serviceLock->Locked();
            } else
                LogInfo("Service seems to be running now.");
        } if (m_serviceLock->Locked()) {
            m_offlineMode = true;
        }
    } catch (...) {
        LogError("Cannot detect off-line mode by lock.");
        m_offlineMode = false;
    }

    if (m_offlineMode)
        LogInfo("Working in off-line mode.");
    else
        LogInfo("Working in on-line mode.");
}

ClientOffline::~ClientOffline()
{
    delete m_serviceLock;
}

bool ClientOffline::isOffline(void)
{
    return m_offlineMode;
}

Credentials ClientOffline::getCredentials()
{
    Credentials creds = Credentials::getCredentialsFromSelf();
    if (isOffline())
        creds.authenticated = true;
    return creds;
}

} // namespace SecurityManager
