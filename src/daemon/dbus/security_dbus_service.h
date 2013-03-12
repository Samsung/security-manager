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
 * @file        security_dbus_service.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @author      Zbigniew Kostrzewa (z.kostrzewa@samsung.com)
 * @version     1.0
 * @brief       This file contains definitions of security DBus service.
 */
#ifndef WRT_SRC_RPC_SECURITY_DBUS_SERVICE_H_
#define WRT_SRC_RPC_SECURITY_DBUS_SERVICE_H_

#include <memory>
#include <vector>
#include <dpl/dbus/connection.h>
#include <dpl/dbus/object.h>
#include <dpl/dbus/dispatcher.h>
#include <dpl/dbus/dbus_interface_dispatcher.h>
#include <security_daemon.h>

class SecurityDBusService : public SecurityDaemon::DaemonService {
private:
    virtual void initialize();
    virtual void start();
    virtual void stop();
    virtual void deinitialize();

private:
    typedef std::shared_ptr<DPL::DBus::InterfaceDispatcher> InterfaceDispatcherPtr;
    typedef std::shared_ptr<DPL::DBus::Dispatcher> DispatcherPtr;

    void addInterface(const std::string& objectPath,
                      const InterfaceDispatcherPtr& dispatcher);

    DPL::DBus::ConnectionPtr m_connection;
    std::vector<DPL::DBus::ObjectPtr> m_objects;
    std::vector<DispatcherPtr> m_dispatchers;
};

#endif // WRT_SRC_RPC_SECURITY_DBUS_SERVICE_H_
