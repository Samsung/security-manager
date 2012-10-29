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
 * @file        ace_api_client.cpp
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of ACE client API
 */

#include <dpl/log/log.h>
#include <ace_popup_handler.h>
#include "ace_api_client.h"
#include "ace-client/ace_client.h"

#include <string>
#include <vector>
#include <dpl/dbus/dbus_client.h>
#include "popup_response_server_api.h"
#include "security_daemon_dbus_config.h"
//#include "PromptModel.h"

ace_return_t ace_client_initialize(ace_popup_handler_func_t handler)
{
    if (!AceClient::AceThinClientSingleton::Instance().isInitialized()) {
        return ACE_INTERNAL_ERROR;
    }
    popup_func = handler;
    // Changed order of checks to make API run with old popup implementation
    // instead of always needing the popup handler to be implemented.
    if (NULL == handler) {
        LogError("NULL argument(s) passed");
        return ACE_INVALID_ARGUMENTS;
    }
    return ACE_OK;
}

ace_return_t ace_client_shutdown(void)
{
    popup_func = NULL;
    return ACE_OK;
}

ace_return_t ace_check_access(const ace_request_t* request, ace_bool_t* access)
{
    if (NULL == request || NULL == access) {
        LogError("NULL argument(s) passed");
        return ACE_INVALID_ARGUMENTS;
    }

    AceClient::AceRequest aceRequest;
    aceRequest.sessionId = request->session_id;
    aceRequest.widgetHandle = request->widget_handle;

    aceRequest.apiFeatures.count = request->feature_list.count;
    aceRequest.apiFeatures.apiFeature =
            const_cast<const char**>(request->feature_list.items);
    aceRequest.functionName = NULL; // TODO will  be removed
    aceRequest.deviceCapabilities.devcapsCount = request->dev_cap_list.count;
    aceRequest.deviceCapabilities.paramsCount = request->dev_cap_list.count;

    char** devCapNames = new char*[request->dev_cap_list.count];
    AceClient::AceParamList* paramList =
            new AceClient::AceParamList[request->dev_cap_list.count];

    unsigned int i;
    for (i = 0; i < request->dev_cap_list.count; ++i) {
        devCapNames[i] = request->dev_cap_list.items[i].name;
        paramList[i].count = request->dev_cap_list.items[i].param_list.count;

        paramList[i].param = new AceClient::AceParam[
                               request->dev_cap_list.items[i].param_list.count];

        unsigned int j;
        for (j = 0; j < request->dev_cap_list.items[i].param_list.count; ++j) {
            paramList[i].param[j].name =
                    request->dev_cap_list.items[i].param_list.items[j].name;
            paramList[i].param[j].value =
                    request->dev_cap_list.items[i].param_list.items[j].value;

        }
    }

    aceRequest.deviceCapabilities.devCapNames =
            const_cast<const char**>(devCapNames);
    aceRequest.deviceCapabilities.params = paramList;

    bool ret = false;

    Try {
        ret = AceClient::AceThinClientSingleton::
                Instance().checkFunctionCall(aceRequest);
        *access = ret ? ACE_TRUE : ACE_FALSE;
    } Catch (AceClient::AceThinClient::Exception::AceThinClientException) {
        LogError("Ace client exception");
        delete [] devCapNames;
        for (i = 0; i < request->dev_cap_list.count; ++i) {
            delete [] paramList[i].param;
        }
        delete [] paramList;
        return ACE_INTERNAL_ERROR;
    }

    delete [] devCapNames;
    for (i = 0; i < request->dev_cap_list.count; ++i) {
        delete [] paramList[i].param;
    }
    delete [] paramList;
    return ACE_OK;
}
