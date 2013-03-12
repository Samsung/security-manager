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
/**
 * @file        security_dbus_service.cpp
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @author      Zbigniew Kostrzewa (z.kostrzewa@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of security DBus service.
 */
#include <dpl/log/log.h>
#include <algorithm>
#include <gio/gio.h>
#include <dpl/exception.h>
#include <dpl/dbus/interface.h>
#include <dpl/dbus/connection.h>
#include "security_dbus_service.h"
#include "security_daemon_dbus_config.h"
#include <ace_server_dbus_interface.h>
#include <ocsp_server_dbus_interface.h>
#include <popup_response_dbus_interface.h>


void SecurityDBusService::start()
{
    LogDebug("SecurityDBusService starting");
    m_connection = DPL::DBus::Connection::systemBus();
    std::for_each(m_objects.begin(),
                  m_objects.end(),
                  [&m_connection] (const DPL::DBus::ObjectPtr& object)
                  {
                      m_connection->registerObject(object);
                  });
    m_connection->registerService(
            WrtSecurity::SecurityDaemonConfig::SERVICE_NAME());
}

void SecurityDBusService::stop()
{
    LogDebug("SecurityDBusService stopping");
    m_connection.reset();
}

void SecurityDBusService::initialize()
{
    LogDebug("SecurityDBusService initializing");
    g_type_init();

    addInterface(WrtSecurity::SecurityDaemonConfig::OBJECT_PATH(),
                 std::make_shared<RPC::AceServerDBusInterface>());
    addInterface(WrtSecurity::SecurityDaemonConfig::OBJECT_PATH(),
                 std::make_shared<RPC::OcspServerDBusInterface>());
    addInterface(WrtSecurity::SecurityDaemonConfig::OBJECT_PATH(),
                 std::make_shared<RPC::PopupResponseDBusInterface>());
}

void SecurityDBusService::addInterface(const std::string& objectPath,
                                       const InterfaceDispatcherPtr& dispatcher)
{
    auto ifaces =
        DPL::DBus::Interface::fromXMLString(dispatcher->getXmlSignature());
    if (ifaces.empty())
    {
        ThrowMsg(DPL::Exception, "No interface description.");
    }

    auto iface = ifaces.at(0);
    iface->setDispatcher(dispatcher.get());

    m_dispatchers.push_back(dispatcher);
    m_objects.push_back(DPL::DBus::Object::create(objectPath, iface));
}

void SecurityDBusService::deinitialize()
{
    LogDebug("SecurityDBusService deinitializing");
    m_objects.clear();
    m_dispatchers.clear();
}

#ifdef DBUS_CONNECTION
DAEMON_REGISTER_SERVICE_MODULE(SecurityDBusService)
#endif //DBUS_CONNECTION
