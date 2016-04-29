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

#include <client-offline.h>
#include <client-common.h>
#include <message-buffer.h>
#include <protocols.h>
#include <connection.h>
#include <dpl/serialization.h>
#include <dpl/log/log.h>

namespace SecurityManager {

ClientOffline::ClientOffline()
{
    offlineMode = false;
    serviceLock = nullptr;

    if (geteuid()) {
        LogInfo("UID != 0, attempting only on-line mode.");
        return;
    }

    try {
        serviceLock = new SecurityManager::FileLocker(SecurityManager::SERVICE_LOCK_FILE, false);
        if (serviceLock->Locked()) {
            int retval;
            MessageBuffer send, recv;

            LogInfo("Service isn't running, try to trigger it via socket activation.");
            serviceLock->Unlock();
            Serialization::Serialize(send, static_cast<int>(SecurityModuleCall::NOOP));
            retval = sendToServer(SERVICE_SOCKET, send.Pop(), recv);
            if (retval != SECURITY_MANAGER_SUCCESS) {
                LogInfo("Socket activation attempt failed.");
                serviceLock->Lock();
                offlineMode = serviceLock->Locked();
            } else
                LogInfo("Service seems to be running now.");
        }
    } catch (...) {
        LogError("Cannot detect off-line mode by lock.");
        offlineMode = false;
    }

    if (offlineMode)
        LogInfo("Working in off-line mode.");
    else
        LogInfo("Working in on-line mode.");
}

ClientOffline::~ClientOffline()
{
    if (serviceLock != nullptr)
        delete serviceLock;
}

bool ClientOffline::isOffline(void)
{
    return offlineMode;
}

Credentials ClientOffline::getCredentials()
{
    Credentials creds = Credentials::getCredentialsFromSelf();
    if (isOffline())
        creds.authenticated = true;
    return creds;
}

} // namespace SecurityManager
