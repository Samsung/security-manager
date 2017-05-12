/*
 *  Copyright (c) 2000 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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

#include <iostream>

#include <socket-manager.h>
#include <file-lock.h>

#include <service.h>

#define REGISTER_SOCKET_SERVICE(manager, service) \
    registerSocketService<service>(manager, #service)

template<typename T>
bool registerSocketService(SecurityManager::SocketManager &manager,
                           const std::string& serviceName)
{
    T *service = NULL;
    try {
        service = new T();
        service->Start();
        manager.RegisterSocketService(service);
        return true;
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
    if (service) {
        service->Stop();
        delete service;
    }
    return false;
}

int main()
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        // initialize logging
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER");

        SecurityManager::FileLocker serviceLock(SecurityManager::SERVICE_LOCK_FILE, true);

        sigset_t mask;
        sigemptyset(&mask);
        sigaddset(&mask, SIGTERM);
        sigaddset(&mask, SIGPIPE);
        if (-1 == pthread_sigmask(SIG_BLOCK, &mask, NULL)) {
            LogError("Error in pthread_sigmask");
            return EXIT_FAILURE;
        }

        LogInfo("Start!");
        SecurityManager::SocketManager manager;

        if (!REGISTER_SOCKET_SERVICE(manager, SecurityManager::Service))
        {
            LogError("Unable to create socket service. Exiting.");
            return EXIT_FAILURE;
        }

        manager.MainLoop();
    } catch (const SecurityManager::FileLocker::Exception::LockFailed &e) {
        LogError("Unable to get a file lock. Exiting.");
        return EXIT_FAILURE;
    } catch (const SecurityManager::FileLocker::Exception::UnlockFailed &e) {
        LogError("Unable to unlock a file. Exiting.");
        return EXIT_FAILURE;
    } catch (const SecurityManager::FileLocker::Exception::Base &e) {
        LogError("Unknown FileLocker exception. Exiting.");
        return EXIT_FAILURE;
    }

    UNHANDLED_EXCEPTION_HANDLER_END
    return EXIT_SUCCESS;
}
