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
 * @file        ace_api_popup_validation.cpp
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of ACE popup validation API.
 */

#include <string>
#include <vector>
#include <dpl/log/log.h>
#include <dpl/dbus/dbus_client.h>
#include "popup_response_server_api.h"
#include "security_daemon_dbus_config.h"
#include "ace_api_popup_validation.h"

namespace {
static DPL::DBus::Client *dbusClient = NULL;
static const int VALIDITY_ONCE_VALUE = 0;
static const int VALIDITY_SESSION_VALUE = 1;
static const int VALIDITY_ALWAYS_VALUE = 1;
} // anonymous

ace_return_t ace_popup_validation_initialize(void)
{
    if (NULL != dbusClient) {
        LogError("ace_api_popup_validation already initialized");
        return ACE_INTERNAL_ERROR;
    }
    Try {
        dbusClient = new DPL::DBus::Client(
                   WrtSecurity::SecurityDaemonConfig::OBJECT_PATH(),
                   WrtSecurity::SecurityDaemonConfig::SERVICE_NAME(),
                   WrtSecurity::PopupServerApi::INTERFACE_NAME());
    } Catch (DPL::DBus::Client::Exception::DBusClientException) {
        LogError("Can't connect to daemon");
        return ACE_INTERNAL_ERROR;
    }

    return ACE_OK; 
}

ace_return_t ace_popup_validation_shutdown(void)
{
    if (NULL == dbusClient) {
        LogError("ace_api_popup_validation not initialized");
        return ACE_INTERNAL_ERROR;
    }
    delete dbusClient;
    dbusClient = NULL;

    return ACE_OK;
}

ace_return_t ace_validate_answer(ace_bool_t answer,
                                 ace_validity_t validity,
                                 const ace_resource_t resource_name,
                                 const ace_session_id_t session_id,
                                 const ace_param_list_t* param_list,
                                 ace_widget_handle_t handle,
                                 ace_bool_t* validation_result)
{
    if (NULL == resource_name ||
        NULL == session_id ||
        NULL == param_list ||
        NULL == validation_result)
    {
        LogError("NULL argument(s) passed");
        return ACE_INVALID_ARGUMENTS;
    }

    bool dbusAnswer = answer == ACE_TRUE;
    int dbusValidity = 0;

    switch (validity) {
    case ACE_ONCE: {
        dbusValidity = VALIDITY_ONCE_VALUE;
        //static_cast<int>(Prompt::Validity::ONCE);
        break; }
    case ACE_SESSION: {
        dbusValidity = VALIDITY_SESSION_VALUE;
        //static_cast<int>(Prompt::Validity::SESSION);
        break; }
    case ACE_ALWAYS: {
        dbusValidity = VALIDITY_ALWAYS_VALUE;
        //static_cast<int>(Prompt::Validity::ALWAYS);
        break; }
    default: {
        LogError("Invalid validity passed");
        return ACE_INVALID_ARGUMENTS; }
    }

    std::string subjectId;
    std::string resourceId(resource_name);
    std::string sessionId(session_id);
    std::vector<std::string> keys, values;
    unsigned int i;
    for (i = 0; i < param_list->count; ++i) {
        keys.push_back(std::string(param_list->items[i].name));
        values.push_back(std::string(param_list->items[i].value));
    }

    bool response = false;
    Try{
        dbusClient->call(WrtSecurity::PopupServerApi::VALIDATION_METHOD(),
                         dbusAnswer,
                         dbusValidity,
                         handle,
                         subjectId,
                         resourceId,
                         keys,
                         values,
                         sessionId,
                         &response);
    } Catch (DPL::DBus::Client::Exception::DBusClientException) {
        LogError("Can't call daemon");
        return ACE_INTERNAL_ERROR;
    }

    *validation_result = response ? ACE_TRUE : ACE_FALSE;

    return ACE_OK;
}
