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
 * @file        ace_client_helper.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains definitions of AceClient helper types and
 *              functions.
 */
#ifndef WRT_ACE_CLIENT_HELPER_H
#define WRT_ACE_CLIENT_HELPER_H

#include <string>
#include <vector>
#include <dpl/foreach.h>

#include <ace-dao-ro/IRequest.h>
#include <ace-dao-ro/PreferenceTypes.h>

#include "ace_client_types.h"

namespace AceClient {

AcePreference toAcePreference(AceDB::PreferenceTypes preference)
{
    switch (preference) {
    case AceDB::PreferenceTypes::PREFERENCE_PERMIT: {
        return PREFERENCE_PERMIT; }
    case AceDB::PreferenceTypes::PREFERENCE_DENY: {
        return PREFERENCE_DENY; }
    case AceDB::PreferenceTypes::PREFERENCE_DEFAULT: {
        return PREFERENCE_DEFAULT; }
    case AceDB::PreferenceTypes::PREFERENCE_BLANKET_PROMPT: {
        return PREFERENCE_BLANKET_PROMPT; }
    case AceDB::PreferenceTypes::PREFERENCE_SESSION_PROMPT: {
        return PREFERENCE_SESSION_PROMPT; }
    case AceDB::PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT: {
        return PREFERENCE_ONE_SHOT_PROMPT; }
    }
    return PREFERENCE_DEFAULT;
}

typedef std::vector<std::string> AceParamKeys;
typedef std::vector<std::string> AceParamValues;

class AceFunctionParam
{
  public:
    virtual ~AceFunctionParam()
    {
    }

    void addAttribute(const std::string& key,
                      const std::string& value)
    {
        m_paramMap.insert(std::make_pair(key, value));
    }

    AceParamKeys getKeys() const
    {
        AceParamKeys out;
        FOREACH (it, m_paramMap) {
            out.push_back(it->first);
        }
        return out;
    }

    AceParamValues getValues() const
    {
        AceParamValues out;
        FOREACH (it, m_paramMap) {
            out.push_back(it->second);
        }
        return out;
    }

    static std::string aceFunctionParamToken;

  private:
    typedef std::multimap<std::string, std::string> ParamMap;
    ParamMap m_paramMap;
};

typedef std::vector <AceFunctionParam> AceFunctionParams;

class AceBasicRequest : public AceDB::IRequest {
  public:
    AceBasicRequest(const AceSubject& subject,
                    const AceResource& resource) :
      m_subject(subject),
      m_resource(resource)
    {
    }

    AceBasicRequest(const AceSubject& subject,
                    const AceResource& resource,
                    const AceFunctionParam& param) :
      m_subject(subject),
      m_resource(resource),
      m_param(param)
    {
    }
    virtual const std::string& getSubjectId() const
    {
        return m_subject;
    }
    virtual const std::string& getResourceId() const
    {
        return m_resource;
    }
    virtual const AceFunctionParam& getFunctionParam() const
    {
        return m_param;
    }

  private:
    AceSubject m_subject;
    AceResource m_resource;
    AceFunctionParam m_param;
};

typedef std::vector <AceBasicRequest> AceBasicRequests;

} // namespace AceClient

#endif // WRT_ACE_CLIENT_HELPER_H
