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
#include <stdlib.h>
#include <signal.h>

#include <dpl/log/log.h>
#include <dpl/log/audit-smack-log.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <socket-manager.h>

#include <data-share.h>
#include <get-gid.h>
#include <privilege-by-pid.h>
#include <app-permissions.h>
#include <cookie.h>
#include <open-for.h>
#include <password.h>

IMPLEMENT_SAFE_SINGLETON(SecurityServer::Log::LogSystem);

int main(void) {

    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        SecurityServer::Singleton<SecurityServer::Log::LogSystem>::Instance().SetTag("SECURITY_SERVER");

        // This provider may be used in security-server only.
        // If we add it inside LogSystem constructor it also
        // will be used by security-server-client library.
        SecurityServer::Log::AuditSmackLog *smackLog = new SecurityServer::Log::AuditSmackLog;
        if (smackLog->Fail())
            delete smackLog;
        else
            SecurityServer::Singleton<SecurityServer::Log::LogSystem>::Instance().AddProvider(smackLog);

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGPIPE);
        if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
            LogError("Error in pthread_sigmask");
            return 1;
        }

        LogInfo("Start!");
        SecurityServer::SocketManager manager;

        SecurityServer::OpenForService *openForService = new SecurityServer::OpenForService;
        openForService->Create();
        manager.RegisterSocketService(openForService);

        SecurityServer::CookieService *cookieService = new SecurityServer::CookieService;
        cookieService->Create();
        manager.RegisterSocketService(cookieService);

        SecurityServer::SharedMemoryService *shmService = new SecurityServer::SharedMemoryService;
        shmService->Create();
        manager.RegisterSocketService(shmService);

        SecurityServer::GetGidService *getGidService = new SecurityServer::GetGidService;
        getGidService->Create();
        manager.RegisterSocketService(getGidService);

        SecurityServer::PrivilegeByPidService *privByPidService = new SecurityServer::PrivilegeByPidService;
        privByPidService->Create();
        manager.RegisterSocketService(privByPidService);

        SecurityServer::AppPermissionsService *appEnablePermissionsService = new SecurityServer::AppPermissionsService;
        appEnablePermissionsService->Create();
        manager.RegisterSocketService(appEnablePermissionsService);

        SecurityServer::PasswordService *pwdService = new SecurityServer::PasswordService;
        pwdService->Create();
        manager.RegisterSocketService(pwdService);

        manager.MainLoop();
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return 0;
}

