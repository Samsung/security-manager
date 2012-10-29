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
 * @file        main.cpp
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       This is main routing for Security Daemon
 */

#include <string>

#include <dpl/application.h>
#include <dpl/log/log.h>
#include <dpl/single_instance.h>
#include <dpl/wrt-dao-ro/global_config.h>

#include "security_daemon.h"

#include <pthread.h>

static const std::string DAEMON_INSTANCE_UUID =
    "5ebf3f24-dad6-4a27-88b4-df7970efe7a9";

extern "C" void *security_server_main_thread(void *data);

int main(int argc, char* argv[])
{

    pthread_t main_thread;

    if (0 != pthread_create(&main_thread, NULL, security_server_main_thread, NULL)) {
        LogError("Cannot create security server thread");
        return -1;
    }

    DPL::SingleInstance instance;
    if (!instance.TryLock(DAEMON_INSTANCE_UUID)) {
        LogError("Security Daemon is already running");
        return -1;
    }

    auto& daemon = SecurityDaemonSingleton::Instance();

    daemon.initialize(argc, argv);

    //Run daemon
    auto retVal = daemon.execute();

    daemon.shutdown();
    instance.Release();

    pthread_exit(NULL);
    return retVal;
}
