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
 * @file        ace_service_dbus_interface.cpp
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       Implementation of ACE server API.
 */
#include <dpl/foreach.h>
#include <vector>
#include <string>
#include "ace_server_dbus_interface.h"
#include <dpl/dbus/dbus_server_deserialization.h>
#include <dpl/dbus/dbus_server_serialization.h>

#include <ace/Request.h>
#include <ace/PolicyResult.h>
#include <security_controller.h>
#include <attribute_facade.h>


namespace RPC {

void AceServerDBusInterface::onMethodCall(const gchar* methodName,
                          GVariant* parameters,
                          GDBusMethodInvocation* invocation)
{
    using namespace WrtSecurity;

    if (0 == g_strcmp0(methodName, AceServerApi::ECHO_METHOD().c_str()))
    {
        std::string str;
        DPL::DBus::ServerDeserialization::deserialize(parameters, &str);
        g_dbus_method_invocation_return_value(invocation,
                DPL::DBus::ServerSerialization::serialize(str));
    } else if (0 == g_strcmp0(methodName,
                              AceServerApi::CHECK_ACCESS_METHOD().c_str()))
    {
        int widgetHandle;
        std::string subject, resource, sessionId;
        std::vector<std::string> paramNames, paramValues;
        if (!DPL::DBus::ServerDeserialization::deserialize(parameters,
                                                      &widgetHandle,
                                                      &subject,
                                                      &resource,
                                                      &paramNames,
                                                      &paramValues,
                                                      &sessionId)) {
            g_dbus_method_invocation_return_dbus_error(
                          invocation,
                          "org.tizen.AceCheckAccessInterface.UnknownError",
                          "Error in deserializing input parameters");
            return;
        }
        if (paramNames.size() != paramValues.size()) {
            g_dbus_method_invocation_return_dbus_error(
                      invocation,
                      "org.tizen.AceCheckAccessInterface.UnknownError",
                      "Varying sizes of parameter names and parameter values");
            return;
        }
        LogDebug("We got subject: " << subject);
        LogDebug("We got resource: " << resource);

        FunctionParamImpl params;
        for (size_t i = 0; i < paramNames.size(); ++i) {
            params.addAttribute(paramNames[i], paramValues[i]);
        }

        Request request(widgetHandle,
                        WidgetExecutionPhase_Invoke,
                        &params);
        request.addDeviceCapability(resource);

        PolicyResult result(PolicyEffect::DENY);
        CONTROLLER_POST_SYNC_EVENT(
            SecurityController,
            SecurityControllerEvents::CheckRuntimeCallSyncEvent(
                &result,
                &request,
                sessionId));

        int response = PolicyResult::serialize(result);
        g_dbus_method_invocation_return_value(invocation,
                DPL::DBus::ServerSerialization::serialize(response));
    } else if (0 == g_strcmp0(methodName,
            AceServerApi::CHECK_ACCESS_INSTALL_METHOD().c_str()))
    {
        int widgetHandle;
        std::string resource;
        if (!DPL::DBus::ServerDeserialization::deserialize(parameters,
                                            &widgetHandle,
                                            &resource)) {
            g_dbus_method_invocation_return_dbus_error(
                    invocation,
                    "org.tizen.AceCheckAccessInterface.UnknownError",
                    "Error in deserializing input parameters");
            return;
        }
        LogDebug("We got handle: " << widgetHandle);
        LogDebug("We got resource: " << resource);

        Request request(widgetHandle,
              WidgetExecutionPhase_WidgetInstall);
        request.addDeviceCapability(resource);

        PolicyResult result(PolicyEffect::DENY);
        CONTROLLER_POST_SYNC_EVENT(
        SecurityController,
        SecurityControllerEvents::CheckFunctionCallSyncEvent(
             &result,
             &request));

        int response = PolicyResult::serialize(result);
        g_dbus_method_invocation_return_value(invocation,
                DPL::DBus::ServerSerialization::serialize(response));
    } else if (0 == g_strcmp0(methodName,
            AceServerApi::UPDATE_POLICY_METHOD().c_str()))
    {
        LogDebug("Policy update DBus message received");
        CONTROLLER_POST_SYNC_EVENT(
                    SecurityController,
                    SecurityControllerEvents::UpdatePolicySyncEvent());
        g_dbus_method_invocation_return_value(invocation, NULL);
    } else {
        // invalid method name
        g_dbus_method_invocation_return_value(invocation, NULL);
    }
}

} // namespace RPC
