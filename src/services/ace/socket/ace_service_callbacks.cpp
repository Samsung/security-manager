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
 * @file        ace_service_callbacks.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of Ace Service callbacks
 */
#include <string>
#include <vector>
#include <dpl/log/log.h>
#include "ace_service_callbacks.h"
#include <callback_api.h>
#include <ace/Request.h>
#include <ace/PolicyResult.h>
#include <security_controller.h>
#include <security_caller.h>
#include <attribute_facade.h>

namespace RPC {

void AceServiceCallbacks::checkAccess(SocketConnection * connector){

    int widgetHandle = 0;
    std::string subject, resource, sessionId;
    std::vector<std::string> paramNames, paramValues;
    Try {
        connector->read(&widgetHandle,
                        &subject,
                        &resource,
                        &paramNames,
                        &paramValues,
                        &sessionId);
    } Catch (SocketConnection::Exception::SocketConnectionException){
        LogError("Socket Connection read error");
        ReThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException,
                   "Socket Connection read error");
    }

    if (paramNames.size() != paramValues.size()) {
        ThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException, "Varying sizes of parameter names and parameter values");
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
    SecurityCallerSingleton::Instance().SendSyncEvent(
        SecurityControllerEvents::CheckRuntimeCallSyncEvent(
            &result,
            &request,
            sessionId));

    int response = PolicyResult::serialize(result);

    Try{
        connector->write(response);
    } Catch (SocketConnection::Exception::SocketConnectionException){
        LogError("Socket Connection write error");
        ReThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException,
                   "Socket Connection write error");
    }
}

void AceServiceCallbacks::checkAccessInstall(SocketConnection * connector){

    int widgetHandle;
    std::string resource;

    Try {
        connector->read(&widgetHandle,
                        &resource);
    } Catch (SocketConnection::Exception::SocketConnectionException){
        LogError("Socket Connection read error");
        ReThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException,
                   "Socket Connection read error");
    }

    LogDebug("We got handle: " << widgetHandle);
    LogDebug("We got resource: " << resource);

    Request request(widgetHandle,
          WidgetExecutionPhase_WidgetInstall);
    request.addDeviceCapability(resource);

    PolicyResult result(PolicyEffect::DENY);
    SecurityCallerSingleton::Instance().SendSyncEvent(
            SecurityControllerEvents::CheckFunctionCallSyncEvent(
                    &result,
                    &request));

    int response = PolicyResult::serialize(result);

    Try{
        connector->write(response);
    }  Catch (SocketConnection::Exception::SocketConnectionException){
        LogError("Socket Connection write error");
        ReThrowMsg(ServiceCallbackApi::Exception::ServiceCallbackException,
                   "Socket Connection write error");
    }
}

void AceServiceCallbacks::updatePolicy(SocketConnection * /*connector*/){


    LogDebug("Policy update socket message received");
    SecurityCallerSingleton::Instance().SendSyncEvent(
            SecurityControllerEvents::UpdatePolicySyncEvent());
}

} //namespace RPC
