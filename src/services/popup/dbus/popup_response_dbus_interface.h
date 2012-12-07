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
 * @file    popup_response_dbus_interface.h
 * @author  Zbigniew Kostrzewa (z.kostrzewa@samsung.com)
 * @author  Tomasz Swierczek (t.swierczek@samsung.com)
 * @version 1.0
 * @brief
 */

#ifndef WRT_SRC_RPC_DAEMON_POPUP_RESPONSE_DBUS_INTERFACE_H
#define WRT_SRC_RPC_DAEMON_POPUP_RESPONSE_DBUS_INTERFACE_H

#include <dpl/dbus/dbus_interface_dispatcher.h>
#include "popup_response_server_api.h"

namespace RPC {

class PopupResponseDBusInterface : public DPL::DBus::InterfaceDispatcher
{
public:
    PopupResponseDBusInterface():
            DPL::DBus::InterfaceDispatcher(
                    WrtSecurity::PopupServerApi::INTERFACE_NAME())
    {
        using namespace WrtSecurity;

        setXmlSignature("<node>"
                 "  <interface name='" +
                         PopupServerApi::INTERFACE_NAME() + "'>"
                 "    <method name='" +
                         PopupServerApi::VALIDATION_METHOD() + "'>"
                         // popup answer data
                 "      <arg type='b' name='allowed' direction='in'/>"
                 "      <arg type='i' name='valid' direction='in'/>"
                         // this is copied from ace_server_dbus_interface
                 "      <arg type='i' name='handle' direction='in'/>"
                 "      <arg type='s' name='subject' direction='in'/>"
                 "      <arg type='s' name='resource' direction='in'/>"
                 "      <arg type='as' name='parameter names' direction='in'/>"
                 "      <arg type='as' name='parameter values' direction='in'/>"
                 "      <arg type='s' name='sessionId' direction='in'/>"
                 "      <arg type='b' name='response' direction='out'/>"
                 "    </method>"
                 "  </interface>"
                 "</node>");

    }

    virtual ~PopupResponseDBusInterface()
    {}

    virtual void onMethodCall(const gchar* methodName,
                              GVariant* parameters,
                              GDBusMethodInvocation* invocation);
};

}

#endif // WRT_SRC_RPC_DAEMON_POPUP_RESPONSE_DBUS_INTERFACE_H
