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
 * @file        ocsp_service_dbus_interface.cpp
 * @author      Piotr Marcinkiewicz (p.marcinkiew@samsung.com)
 * @version     1.0
 * @brief       Implementation of OCSP server API.
 */
#include "ocsp_server_dbus_interface.h"

namespace RPC {

using namespace WrtSecurity;

OcspServerDBusInterface::OcspServerDBusInterface():
    DPL::DBus::InterfaceDispatcher(OcspServerApi::INTERFACE_NAME())
{
    setXmlSignature("<node>"
        "  <interface name='" + OcspServerApi::INTERFACE_NAME() + "'>"
        "    <method name='" + OcspServerApi::ECHO_METHOD() + "'>"
        "      <arg type='s' name='input' direction='in'/>"
        "      <arg type='s' name='output' direction='out'/>"
        "    </method>"
        "    <method name='" + OcspServerApi::CHECK_ACCESS_METHOD() + "'>"
        "      <arg type='i' name='input' direction='in'/>"
        "      <arg type='i' name='output' direction='out'/>"
        "    </method>"
        "  </interface>"
        "</node>");
}


void OcspServerDBusInterface::onMethodCall(
        const gchar* argMethodName,
        GVariant* argParameters,
        GDBusMethodInvocation* argInvocation)
{
    if (OcspServerApi::ECHO_METHOD() == argMethodName){
        // TODO: Deserialization should use
        // DBus::SErverDeserialization::deserialize()
        const gchar* arg = NULL;
        g_variant_get(argParameters, "(&s)", &arg);
        // TODO: Serialization should use
        // DBus::SErverDeserialization::serialize()
        gchar* response = g_strdup_printf(arg);
        g_dbus_method_invocation_return_value(argInvocation,
                                              g_variant_new ("(s)", response));
        g_free (response);
    } else if (OcspServerApi::CHECK_ACCESS_METHOD() == argMethodName) {
        gint32 value;
        g_variant_get(argParameters, "(i)", &value);

        // TODO: this is making OCSP service a stub! this HAS to be moved
        // with proper implementation to cert-svc daemon
        gint32 response = 0; // Certificates are valid for now

        GVariant* varResponse = g_variant_new ("(i)", response);
                //This function will unref invocation and it will be freed
        LogDebug("OCSP dbus interface tries to send result");
        g_dbus_method_invocation_return_value(argInvocation, varResponse);
    }
}

} // namespace RPC
