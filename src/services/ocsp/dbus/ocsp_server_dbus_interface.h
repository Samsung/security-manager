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
 * @file        ocsp_service_dbus_interface.h
 * @author      Piotr Marcinkiewicz (p.marcinkiew@samsung.com)
 * @version     1.0
 * @brief       Class that handles OCSP server API.
 */
#ifndef WRT_SRC_RPC_SECURITY_DAEMON_OCSP_SERVER_DBUS_INTERFACE_H_
#define WRT_SRC_RPC_SECURITY_DAEMON_OCSP_SERVER_DBUS_INTERFACE_H_

#include <list>
#include <dpl/dbus/dbus_interface_dispatcher.h>
#include "api/ocsp_server_dbus_api.h"

namespace RPC {

class OcspServerDBusInterface :
    public DPL::DBus::InterfaceDispatcher
{
  public:
    OcspServerDBusInterface();

    virtual ~OcspServerDBusInterface()
    {}

    virtual void onMethodCall(const gchar* method_name,
                              GVariant* parameters,
                              GDBusMethodInvocation* invocation);
};

} // namespace RPC

#endif // WRT_SRC_RPC_SECURITY_DAEMON_OCSP_SERVER_DBUS_INTERFACE_H_
