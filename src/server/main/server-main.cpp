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
 * @file        server-main.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of security-manager on basis of security-server
 */
#include <stdlib.h>
#include <signal.h>

#include <dpl/log/log.h>
#include <dpl/singleton.h>
#include <dpl/singleton_safe_impl.h>

#include <socket-manager.h>

#include <service.h>

IMPLEMENT_SAFE_SINGLETON(SecurityManager::Log::LogSystem);

#define REGISTER_SOCKET_SERVICE(manager, service) \
    registerSocketService<service>(manager, #service)

template<typename T>
void registerSocketService(SecurityManager::SocketManager &manager, const std::string& serviceName)
{
    T *service = NULL;
    try {
        service = new T();
        service->Create();
        manager.RegisterSocketService(service);
        service = NULL;
    } catch (const SecurityManager::Exception &exception) {
        LogError("Error in creating service " << serviceName <<
                 ", details:\n" << exception.DumpToString());
    } catch (const std::exception& e) {
        LogError("Error in creating service " << serviceName <<
                 ", details:\n" << e.what());
    } catch (...) {
        LogError("Error in creating service " << serviceName <<
                 ", unknown exception occured");
    }
    if (service)
        delete service;
}

int main(void) {

    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER");

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGPIPE);
        if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
            LogError("Error in pthread_sigmask");
            return 1;
        }

        LogInfo("Start!");
        SecurityManager::SocketManager manager;

        REGISTER_SOCKET_SERVICE(manager, SecurityManager::Service);

        manager.MainLoop();
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return 0;
}
