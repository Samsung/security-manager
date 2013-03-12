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
 * @file        ace_service_dbus_interface.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       Class that handles ACE server API.
 */
#ifndef WRT_SRC_RPC_SECURITY_DAEMON_ACE_SERVER_DBUS_INTERFACE_H_
#define WRT_SRC_RPC_SECURITY_DAEMON_ACE_SERVER_DBUS_INTERFACE_H_

#include <dpl/dbus/dbus_interface_dispatcher.h>
#include "api/ace_server_dbus_api.h"

namespace RPC {

class AceServerDBusInterface : public DPL::DBus::InterfaceDispatcher {
  public:
    AceServerDBusInterface():
        DPL::DBus::InterfaceDispatcher(WrtSecurity::AceServerApi::INTERFACE_NAME())
    {
        using namespace WrtSecurity;

        setXmlSignature("<node>"
            "  <interface name='" + AceServerApi::INTERFACE_NAME() + "'>"
            "    <method name='" + AceServerApi::ECHO_METHOD() + "'>"
            "      <arg type='s' name='input' direction='in'/>"
            "      <arg type='s' name='output' direction='out'/>"
            "    </method>"
            "    <method name='" + AceServerApi::CHECK_ACCESS_METHOD() + "'>"
            "      <arg type='i' name='handle' direction='in'/>"
            "      <arg type='s' name='subject' direction='in'/>"
            "      <arg type='s' name='resource' direction='in'/>"
            "      <arg type='as' name='parameter names' direction='in'/>"
            "      <arg type='as' name='parameter values' direction='in'/>"
            "      <arg type='s' name='session' direction='in'/>"
            "      <arg type='i' name='output' direction='out'/>"
            "    </method>"
            "    <method name='" + AceServerApi::CHECK_ACCESS_INSTALL_METHOD() + "'>"
            "      <arg type='i' name='handle' direction='in'/>"
            "      <arg type='s' name='resource' direction='in'/>"
            "      <arg type='i' name='output' direction='out'/>"
            "    </method>"
            "    <method name='" + AceServerApi::UPDATE_POLICY_METHOD() + "'>"
            "    </method>"
            "  </interface>"
            "</node>");
    }

    virtual ~AceServerDBusInterface()
    {}

    virtual void onMethodCall(const gchar* methodName,
                              GVariant* parameters,
                              GDBusMethodInvocation* invocation);
};

} // namespace RPC

#endif // WRT_SRC_RPC_SECURITY_DAEMON_ACE_SERVER_DBUS_INTERFACE_H_
