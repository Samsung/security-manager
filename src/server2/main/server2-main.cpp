/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        sever2-main.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of security-server2
 */

#include <server2-main.h>

#include <dpl/log/log.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <service-thread.h>
#include <socket-manager.h>

#include <data-share.h>
#include <echo.h>

IMPLEMENT_SAFE_SINGLETON(SecurityServer::Log::LogSystem);

int server2(void) {
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        SecurityServer::Singleton<SecurityServer::Log::LogSystem>::Instance().SetTag("SECURITY_SERVER2");
        LogInfo("Start!");
        SecurityServer::SocketManager manager;

//        This will be used only by tests
//        SecurityServer::EchoService *echoService = new SecurityServer::EchoService;
//        echoService->Create();
//        manager.RegisterSocketService(echoService);

        SecurityServer::SharedMemoryService *shmService = new SecurityServer::SharedMemoryService;
        shmService->Create();
        manager.RegisterSocketService(shmService);

        manager.MainLoop();
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return 0;
}

