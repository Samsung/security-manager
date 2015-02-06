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

#include <boost/program_options.hpp>
#include <iostream>

#include <socket-manager.h>
#include <file-lock.h>

#include <service.h>
#include <master-service.h>

namespace po = boost::program_options;

IMPLEMENT_SAFE_SINGLETON(SecurityManager::Log::LogSystem);

#define REGISTER_SOCKET_SERVICE(manager, service, allocator) \
    registerSocketService<service>(manager, #service, allocator)

template<typename T>
bool registerSocketService(SecurityManager::SocketManager &manager,
                           const std::string& serviceName,
                           const std::function<T*(void)>& serviceAllocator)
{
    T *service = NULL;
    try {
        service = serviceAllocator();
        service->Create();
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
    if (service)
        delete service;
    return false;
}

int main(int argc, char* argv[])
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        // initialize logging
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER");

        // parse arguments
        bool masterMode = false, slaveMode = false;
        po::options_description optDesc("Allowed options");

        optDesc.add_options()
        ("help,h", "Print this help message")
        ("master,m", "Enable master mode")
        ("slave,s", "Enable slave mode")
        ;

        po::variables_map vm;
        po::basic_parsed_options<char> parsed =
                po::command_line_parser(argc, argv).options(optDesc).allow_unregistered().run();

        std::vector<std::string> unrecognizedOptions =
             po::collect_unrecognized(parsed.options, po::include_positional);

        if (!unrecognizedOptions.empty()) {
            std::cerr << "Unrecognized options: ";

            for (auto& uo : unrecognizedOptions) {
                std::cerr << ' ' << uo;
            }

            std::cerr << std::endl << std::endl;
            std::cerr << optDesc << std::endl;

            return EXIT_FAILURE;
        }

        po::store(parsed, vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << optDesc << std::endl;
            return EXIT_SUCCESS;
        }

        masterMode = vm.count("master") > 0;
        slaveMode = vm.count("slave") > 0;

        if (masterMode && slaveMode) {
            LogError("Cannot be both master and slave!");
            return EXIT_FAILURE;
        }

        SecurityManager::FileLocker serviceLock(SecurityManager::SERVICE_LOCK_FILE,
                                                true);

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

        if (masterMode) {
            if (!REGISTER_SOCKET_SERVICE(manager, SecurityManager::MasterService,
                    []() { return new SecurityManager::MasterService(); } )) {
                LogError("Unable to create master socket service. Exiting.");
                return EXIT_FAILURE;
            }
        } else {
            if (!REGISTER_SOCKET_SERVICE(manager, SecurityManager::Service,
                    [&slaveMode]() { return new SecurityManager::Service(slaveMode); } )) {
                LogError("Unable to create socket service. Exiting.");
                return EXIT_FAILURE;
            }
        }

        manager.MainLoop();
    } catch (const SecurityManager::FileLocker::Exception::Base &e) {
        LogError("Unable to get a file lock. Exiting.");
        return EXIT_FAILURE;
    }
    UNHANDLED_EXCEPTION_HANDLER_END
    return EXIT_SUCCESS;
}
