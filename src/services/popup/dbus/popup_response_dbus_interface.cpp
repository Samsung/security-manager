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
 * @file    popup_response_dispatcher.cpp
 * @author  Zbigniew Kostrzewa (z.kostrzewa@samsung.com)
 * @version 1.0
 * @brief
 */

#include "popup_response_dbus_interface.h"
#include <vector>
#include <string>
#include <dpl/dbus/dbus_server_deserialization.h>
#include <dpl/dbus/dbus_server_serialization.h>
#include <ace/Request.h>
#include <ace-dao-ro/PromptModel.h>
#include "popup_ace_data_types.h"
//#include "access-control/engine/PromptModel.h"
#include "attribute_facade.h"
//#include "Request.h"
#include "security_controller.h"

namespace RPC
{

void PopupResponseDBusInterface::onMethodCall(const gchar* methodName,
                                           GVariant* parameters,
                                           GDBusMethodInvocation* invocation)
{
    using namespace WrtSecurity;
#if 1
    if (0 == g_strcmp0(methodName,
            PopupServerApi::VALIDATION_METHOD().c_str()))
    {
        // popup answer data
        bool allowed = false;
        int serializedValidity = 0;

        // ACE data
        AceUserdata acedata;

        if (!DPL::DBus::ServerDeserialization::deserialize(
                parameters,
                &allowed,
                &serializedValidity,
                &(acedata.handle),
                &(acedata.subject),
                &(acedata.resource),
                &(acedata.paramKeys),
                &(acedata.paramValues),
                &(acedata.sessionId)))
        {
            g_dbus_method_invocation_return_dbus_error(
                          invocation,
                          "org.tizen.PopupResponse.UnknownError",
                          "Error in deserializing input parameters");
            return;
        }

        if (acedata.paramKeys.size() != acedata.paramValues.size()) {
            g_dbus_method_invocation_return_dbus_error(
                      invocation,
                      "org.tizen.PopupResponse.UnknownError",
                      "Varying sizes of parameter names and parameter values");
            return;
        }

        FunctionParamImpl params;
        for (size_t i = 0; i < acedata.paramKeys.size(); ++i) {
            params.addAttribute(acedata.paramKeys[i], acedata.paramValues[i]);
        }
        Request request(acedata.handle,
                        WidgetExecutionPhase_Invoke,
                        &params);
        request.addDeviceCapability(acedata.resource);

        Prompt::Validity validity = static_cast<Prompt::Validity>(serializedValidity);

        bool response = false;
        SecurityControllerEvents::ValidatePopupResponseEvent ev(
            &request,
            allowed,
            validity,
            acedata.sessionId,
            &response);
        CONTROLLER_POST_SYNC_EVENT(SecurityController, ev);

        g_dbus_method_invocation_return_value(
            invocation,
            DPL::DBus::ServerSerialization::serialize(response));
    }
#endif
}

}
