/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
/*
 * @file        ace_service.cpp
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       This is implementation file of AceService service
 */

#include <dpl/log/log.h>
#include <security_controller.h>

#include "security_daemon.h"

namespace AceService
{

class AceService : public SecurityDaemon::DaemonService
{
  private:
    virtual void initialize()
    {
        LogDebug("AceService initializing");

        SecurityControllerSingleton::Instance().Touch();
        SecurityControllerSingleton::Instance().SwitchToThread(NULL);

        CONTROLLER_POST_SYNC_EVENT(
            SecurityController,
            SecurityControllerEvents::InitializeSyncEvent());
    }

    virtual void start()
    {
        LogDebug("Starting AceService");
    }

    virtual void stop()
    {
        LogDebug("Stopping AceService");
    }

    virtual void deinitialize()
    {
        LogDebug("AceService deinitializing");
        SecurityControllerSingleton::Instance().SwitchToThread(NULL);
        //this is direct call inside
        CONTROLLER_POST_SYNC_EVENT(
            SecurityController,
            SecurityControllerEvents::TerminateSyncEvent());
    }

};

DAEMON_REGISTER_SERVICE_MODULE(AceService)

}//namespace AceService
