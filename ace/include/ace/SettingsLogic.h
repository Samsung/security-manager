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
 * @file       SettingsLogic.h
 * @author     Tomasz Swierczek (t.swierczek@samsung.com)
 * @version    0.1
 * @brief      Header file for class getting/setting user/global ACE settings
 */

#ifndef WRT_SRC_ACCESS_CONTROL_LOGIC_SETTINGS_LOGIC_H_
#define WRT_SRC_ACCESS_CONTROL_LOGIC_SETTINGS_LOGIC_H_

#include <set>
#include <list>
#include <map>
#include <string>
#include <ace-dao-ro/PreferenceTypes.h>
#include <ace/Request.h>
#include <ace/PermissionTriple.h>
#include <ace-dao-rw/AceDAO.h>
#include <ace-dao-ro/common_dao_types.h>

class SettingsLogic
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, DatabaseError)
    };

    // global settings
    static AceDB::PreferenceTypes findGlobalUserSettings(
            const std::string &resource,
            WidgetHandle handler);

    static AceDB::PreferenceTypes findGlobalUserSettings(
            const Request &request);

    // resource settings
    static AceDB::PreferenceTypes getDevCapSetting(
            const std::string &request);
    static void getDevCapSettings(AceDB::PreferenceTypesMap *preferences);
    static void setDevCapSetting(const std::string &resource,
            AceDB::PreferenceTypes preference);
    static void setAllDevCapSettings(
            const std::list<std::pair<const std::string *,
                    AceDB::PreferenceTypes> > &resourcesList);
    static void removeDevCapSetting(const std::string &resource);
    static void updateDevCapSetting(const std::string &resource,
            AceDB::PreferenceTypes p);

    // user settings
    static AceDB::PreferenceTypes getWidgetDevCapSetting(
            const std::string &resource,
            WidgetHandle handler);
    static void getWidgetDevCapSettings(PermissionList *permissions);
    static void setWidgetDevCapSetting(const std::string &resource,
            WidgetHandle handler,
            AceDB::PreferenceTypes preference);
    static void setWidgetDevCapSettings(const PermissionList &tripleList);
    static void removeWidgetDevCapSetting(const std::string &resource,
            WidgetHandle handler);

  private:
    SettingsLogic()
    {
    }

};

#endif /* WRT_SRC_ACCESS_CONTROL_LOGIC_SETTINGS_LOGIC_H_ */
