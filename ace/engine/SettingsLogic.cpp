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
 *
 *
 * @file       SettingsLogic.cpp
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.1
 * @brief      SettingsLogic implementation
 */

#include <ace/SettingsLogic.h>

#include <dpl/log/log.h>
#include <dpl/foreach.h>

#include <ace/Preference.h>

using namespace AceDB;

Preference SettingsLogic::findGlobalUserSettings(
        const std::string &resource,
        WidgetHandle handler)
{
    Preference p = AceDAO::getWidgetDevCapSetting(resource, handler);
    if (PreferenceTypes::PREFERENCE_DEFAULT == p) {
        return AceDAO::getDevCapSetting(resource);
    } else {
        return p;
    }
}

Preference SettingsLogic::findGlobalUserSettings(
        const Request &request)
{
    Request::DeviceCapabilitySet devset = request.getDeviceCapabilitySet();
    Assert(!devset.empty() && "No device cap set in request");
    return findGlobalUserSettings(
        *(devset.begin()),
        request.getWidgetHandle());
}

Preference SettingsLogic::getDevCapSetting(const std::string &resource)
{
    return AceDAO::getDevCapSetting(resource);
}

void SettingsLogic::getDevCapSettings(PreferenceMap *globalSettingsMap)
{
    AceDAO::getDevCapSettings(globalSettingsMap); // NULL check inside
}


void SettingsLogic::setDevCapSetting(const std::string &resource,
                                       Preference preference)
{
    if (resource.empty()) {
        LogInfo("WARNING: setting resource settings for empty resource name");
    }

    AceDAO::addResource(resource);

    if (preference == PreferenceTypes::PREFERENCE_DEFAULT) {
        return;
    }

    Assert((PreferenceTypes::PREFERENCE_PERMIT == preference ||
            PreferenceTypes::PREFERENCE_DENY == preference ||
            PreferenceTypes::PREFERENCE_BLANKET_PROMPT == preference ||
            PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT == preference ||
            PreferenceTypes::PREFERENCE_SESSION_PROMPT == preference));

    AceDAO::setDevCapSetting(resource,preference);
}

void SettingsLogic::setAllDevCapSettings(
    const std::list < std::pair < const std::string*,
    Preference > > &resourcesList)
{
    std::list < std::pair < const std::string*,
        Preference > >::const_iterator iter;
    for (iter = resourcesList.begin(); iter != resourcesList.end(); ++iter) {
        SettingsLogic::setDevCapSetting(*(iter->first), iter->second);
    }
}

void SettingsLogic::removeDevCapSetting(const std::string &resource)
{
    AceDAO::removeDevCapSetting(resource);
}

void SettingsLogic::updateDevCapSetting(const std::string &resource,
                                        Preference p)
{
    if (PreferenceTypes::PREFERENCE_DEFAULT == p) {
        SettingsLogic::removeDevCapSetting(resource);
    } else {
        SettingsLogic::setDevCapSetting(resource, p);
    }
}

Preference SettingsLogic::getWidgetDevCapSetting(
        const std::string &resource,
        WidgetHandle handler)
{
    return AceDAO::getWidgetDevCapSetting(resource, handler);
}

void SettingsLogic::getWidgetDevCapSettings(PermissionList *outputList)
{
    AceDAO::getWidgetDevCapSettings(outputList); // NULL check inside
}


void SettingsLogic::setWidgetDevCapSetting(
        const std::string &resource,
        WidgetHandle handler,
        Preference preference)
{
    if (resource.empty()) {
        LogError("Empty resource");
        return;
    }

    LogDebug("userSetting, resource: " << resource <<
             " app_id: " << handler);

    AceDAO::addResource(resource);
    SettingsLogic::removeWidgetDevCapSetting(resource, handler);

    if (PreferenceTypes::PREFERENCE_DEFAULT == preference) {
        return;
    }

    Assert((PreferenceTypes::PREFERENCE_PERMIT == preference ||
            PreferenceTypes::PREFERENCE_DENY == preference ||
            PreferenceTypes::PREFERENCE_BLANKET_PROMPT == preference ||
            PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT == preference ||
            PreferenceTypes::PREFERENCE_SESSION_PROMPT == preference));

    AceDAO::setWidgetDevCapSetting(resource, handler, preference);
}


void SettingsLogic::setWidgetDevCapSettings(const PermissionList &permissionsList)
{
    FOREACH(i, permissionsList) {
        SettingsLogic::setWidgetDevCapSetting(i->devCap,
                i->appId,
                i->access);
    }
}


void SettingsLogic::removeWidgetDevCapSetting(const std::string &resource,
                                              WidgetHandle handler)
{
    AceDAO::removeWidgetDevCapSetting(resource, handler);
}
