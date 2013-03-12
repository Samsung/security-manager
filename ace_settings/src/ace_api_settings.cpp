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
 * @file        ace_api_settings.cpp
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation ACE settings API
 */

#include <string>
#include <dpl/log/log.h>
#include <ace-dao-rw/AceDAO.h>

#include "ace_api_settings.h"

// helper functions
static ace_preference_t to_ace_preference(const AceDB::PreferenceTypes& db_preference)
{
    switch (db_preference) {
    case AceDB::PreferenceTypes::PREFERENCE_BLANKET_PROMPT: {
        return ACE_PREFERENCE_BLANKET_PROMPT; }
    case AceDB::PreferenceTypes::PREFERENCE_DEFAULT: {
        return ACE_PREFERENCE_DEFAULT;}
    case AceDB::PreferenceTypes::PREFERENCE_DENY: {
        return ACE_PREFERENCE_DENY;}
    case AceDB::PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT: {
        return ACE_PREFERENCE_ONE_SHOT_PROMPT;}
    case AceDB::PreferenceTypes::PREFERENCE_PERMIT: {
        return ACE_PREFERENCE_PERMIT;}
    case AceDB::PreferenceTypes::PREFERENCE_SESSION_PROMPT: {
        return ACE_PREFERENCE_SESSION_PROMPT;}
    default: {
        return ACE_PREFERENCE_DEFAULT;}
    }
}


static AceDB::PreferenceTypes to_ace_db_preference(const ace_preference_t& preference)
{
    switch (preference) {
    case ACE_PREFERENCE_BLANKET_PROMPT: {
        return AceDB::PreferenceTypes::PREFERENCE_BLANKET_PROMPT; }
    case ACE_PREFERENCE_DEFAULT: {
        return AceDB::PreferenceTypes::PREFERENCE_DEFAULT;}
    case ACE_PREFERENCE_DENY: {
        return AceDB::PreferenceTypes::PREFERENCE_DENY;}
    case ACE_PREFERENCE_ONE_SHOT_PROMPT: {
        return AceDB::PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT;}
    case ACE_PREFERENCE_PERMIT: {
        return AceDB::PreferenceTypes::PREFERENCE_PERMIT;}
    case ACE_PREFERENCE_SESSION_PROMPT: {
        return AceDB::PreferenceTypes::PREFERENCE_SESSION_PROMPT;}
    default: {
        return AceDB::PreferenceTypes::PREFERENCE_DEFAULT;}
    }
}

ace_return_t ace_settings_initialize(void)
{
    AceDB::AceDAO::attachToThreadRW();
    return ACE_OK;
}

ace_return_t ace_settings_shutdown(void)
{
    AceDB::AceDAO::detachFromThread();
    return ACE_OK;
}

ace_return_t ace_get_widget_resource_preference(ace_widget_handle_t handle,
                                                const ace_resource_t resource,
                                                ace_preference_t* preference)
{
    if (NULL == resource || NULL == preference) {
        LogError("NULL argument(s) passed");
        return ACE_INVALID_ARGUMENTS;
    }
    Try {
        std::string resource_str(resource);
        AceDB::PreferenceTypes db_preference =
                AceDB::AceDAO::getWidgetDevCapSetting(resource_str, handle);
        *preference = to_ace_preference(db_preference);
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_get_global_resource_preference(const ace_resource_t resource,
                                                ace_preference_t* preference)
{
    if (NULL == resource || NULL == preference) {
        LogError("NULL argument(s) passed");
        return ACE_INVALID_ARGUMENTS;
    }
    Try {
        AceDB::PreferenceTypes db_preference =
                AceDB::AceDAO::getDevCapSetting(resource);
        *preference = to_ace_preference(db_preference);
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_set_widget_resource_preference(ace_widget_handle_t handle,
                                                const ace_resource_t resource,
                                                ace_preference_t preference)
{
    if (NULL == resource) {
        LogError("NULL argument passed");
        return ACE_INVALID_ARGUMENTS;
    }
    Try {
        AceDB::AceDAO::addResource(resource);
        AceDB::PreferenceTypes db_preference = to_ace_db_preference(preference);
        AceDB::AceDAO::removeWidgetDevCapSetting(resource, handle);
        AceDB::AceDAO::setWidgetDevCapSetting(resource, handle, db_preference);
    } Catch(AceDB::AceDAO::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_set_global_resource_preference(const ace_resource_t resource,
                                                ace_preference_t preference)
{
    if (NULL == resource) {
        LogError("NULL argument passed");
        return ACE_INVALID_ARGUMENTS;
    }
    Try {
        AceDB::AceDAO::addResource(resource);
        AceDB::PreferenceTypes db_preference = to_ace_db_preference(preference);
        AceDB::AceDAO::setDevCapSetting(resource, db_preference);
    } Catch(AceDB::AceDAO::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_reset_widget_resource_settings()
{
    Try {
        AceDB::AceDAO::clearWidgetDevCapSettings();
    } Catch(AceDB::AceDAO::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_reset_global_resource_settings(void)
{
    Try {
        AceDB::AceDAO::clearDevCapSettings();
    } Catch(AceDB::AceDAO::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_is_private_api(const ace_resource_t resource_name, ace_bool_t* is_private_api)
{
    static const char * const private_api[] = {
        "bluetooth.admin",
        "bluetooth.gap",
        "bluetooth.spp",
        "calendar.read",
        "calendar.write",
        "callhistory.read",
        "callhistory.write",
        "contact.read",
        "contact.write",
        "nfc.admin",
        "nfc.common",
        "nfc.cardemulation",
        "nfc.p2p",
        "nfc.tag",
        NULL
    };

    *is_private_api = ACE_TRUE;
    for (int i=0; private_api[i]; ++i)
        if (!strcmp(resource_name, private_api[i]))
            return ACE_OK;

    *is_private_api = ACE_FALSE;
    return ACE_OK;
}

