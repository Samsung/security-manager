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
 * @file        ace_client_types.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains definitions of AceClient types
 */
#ifndef WRT_ACE_CLIENT_TYPES_H
#define WRT_ACE_CLIENT_TYPES_H

#include <string>
#include <utility>
#include <map>

namespace AceClient {

typedef int   AceWidgetHandle;
typedef void* AceJobWidgetInstallId;

typedef std::string AceResource;
typedef std::string AceSubject;
typedef std::string AceSessionId;

enum AcePreference
{
    PREFERENCE_PERMIT,
    PREFERENCE_DENY,
    PREFERENCE_DEFAULT,
    PREFERENCE_BLANKET_PROMPT,
    PREFERENCE_SESSION_PROMPT,
    PREFERENCE_ONE_SHOT_PROMPT
};

typedef std::map<std::string, AcePreference>  AceResourcesPreferences;
typedef std::pair<std::string, AcePreference> AceResurcePreference;

struct AceParam
{
    const char *name;
    const char *value;

    AceParam():
        name(NULL), value(NULL)
    {}

    AceParam(const char *name, const char *value):
        name(name), value(value)
    {}
};

struct AceParamList
{
    size_t    count;
    AceParam* param;
    AceParamList():
        count(0),
        param(NULL)
    {}
};

struct AceDeviceCap
{
    size_t        devcapsCount;
    const char**  devCapNames;
    size_t        paramsCount;
    AceParamList* params;
    AceDeviceCap():
        devcapsCount(0),
        devCapNames(NULL),
        paramsCount(0),
        params(NULL)
    {}
};

struct AceApiFeatures
{
    size_t       count;
    const char** apiFeature;
    AceApiFeatures():
        count(0),
        apiFeature(NULL)
    {}
};

struct AceRequest
{
    AceSessionId    sessionId;
    AceWidgetHandle widgetHandle;
    AceApiFeatures  apiFeatures;
    const char*     functionName;
    AceDeviceCap    deviceCapabilities;
    AceRequest():
        widgetHandle(0),
        apiFeatures(),
        functionName(NULL),
        deviceCapabilities()
    {}
};

} // namespace AceClient

#endif // WRT_ACE_CLIENT_TYPES_H
