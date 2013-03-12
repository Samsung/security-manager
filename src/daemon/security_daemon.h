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
 * @file        security_daemon.h
 * @author      Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version     1.0
 * @brief       This is header file of Security Daemon
 */

#ifndef WRT_SRC_SECURITY_DAEMON_SECURITY_DAEMON_H
#define WRT_SRC_SECURITY_DAEMON_SECURITY_DAEMON_H

#include <utility>
#include <memory>
#include <list>
#include <dpl/noncopyable.h>
#include <dpl/singleton.h>
#include <dpl/assert.h>


namespace SecurityDaemon {

class DaemonService : DPL::Noncopyable {
  public:
    virtual void initialize() = 0;
    virtual void start() = 0;
    virtual void stop() = 0;
    virtual void deinitialize() = 0;
};

class SecurityDaemon : DPL::Noncopyable
{
  public:
    SecurityDaemon();

    void initialize(int& argc, char** argv);
    int execute();
    void terminate(int returnValue = 0);

    template<typename ServiceType, typename ...Args>
    void registerService(Args&&... args)
    {
        Assert(!m_initialized && "Too late for registration");

        m_servicesList.push_back(
                std::make_shared<ServiceType>(std::forward<Args>(args)...));
    }

    void shutdown();

  private:
    bool m_initialized;
    bool m_terminating;
    int m_returnValue;
    typedef std::list<std::shared_ptr<DaemonService>> DaemonServiceList;
    DaemonServiceList m_servicesList;
};

namespace DatabaseService {
    void initialize();
    void deinitialize();
};

} //namespace SecurityDaemon

typedef DPL::Singleton<SecurityDaemon::SecurityDaemon> SecurityDaemonSingleton;

#define DAEMON_REGISTER_SERVICE_MODULE(Type)                                \
    namespace {                                                             \
        static int initializeModule();                                      \
        static int initializeModuleHelper = initializeModule();             \
        int initializeModule()                                              \
        {                                                                   \
            (void)initializeModuleHelper;                                   \
            SecurityDaemonSingleton::Instance().registerService<Type>();    \
            return 0;                                                       \
        }                                                                   \
    }


#endif /* WRT_SRC_SECURITY_DAEMON_SECURITY_DAEMON_H */
