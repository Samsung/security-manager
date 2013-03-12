/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        popup_service_callbacks.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of Popup Service callbacks
 */

#include "popup_service_callbacks.h"
#include <callback_api.h>
#include <ace/Request.h>
#include <ace-dao-ro/PromptModel.h>
#include <dpl/log/log.h>
#include "attribute_facade.h"
#include "popup_ace_data_types.h"
#include "security_controller.h"
#include <security_caller.h>

namespace RPC {

void PopupServiceCallbacks::validate(SocketConnection * connector){

    bool allowed = false;
    int serializedValidity = 0;

    AceUserdata acedata;

    Try {
        connector->read(&allowed,
                        &serializedValidity,
                        &(acedata.handle),
                        &(acedata.subject),
                        &(acedata.resource),
                        &(acedata.paramKeys),
                        &(acedata.paramValues),
                        &(acedata.sessionId));
    } Catch (SocketConnection::Exception::SocketConnectionException){
        LogError("Socket connection read error");
        ReThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException,
                   "Socket connection read error");
    }

    if (acedata.paramKeys.size() != acedata.paramValues.size()) {
        ThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException,
                 "Varying sizes of parameter names vector and parameter values vector");
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
    SecurityCallerSingleton::Instance().SendSyncEvent(ev);

    Try {
        connector->write(response);
    } Catch (SocketConnection::Exception::SocketConnectionException){
        LogError("Socket connection write error");
        ReThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException,
                   "Socket connection write error");
    }
}

} // namespace RPC
