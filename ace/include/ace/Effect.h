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
//
//
//
//  @ Project : Access Control Engine
//  @ File Name : Effect.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#ifndef _EFFECT_H_
#define _EFFECT_H_

#include <list>

typedef int RuleId;

enum Effect
{
    Deny =0,
    Undetermined=1,    // jk mb added this enum, so the ones below are inceremented!!!!!!!
    PromptOneShot =2,
    PromptSession =3,
    PromptBlanket =4,
    Permit =5,
    Inapplicable =6,
    NotMatchingTarget=7,
    Error=8,
};

struct ExtendedEffect {
public:
    ExtendedEffect(Effect effect = Error, RuleId ruleId = -1)
      : m_effect(effect)
      , m_ruleId(ruleId)
    {}

    ExtendedEffect(const ExtendedEffect &second)
      : m_effect(second.m_effect)
      , m_ruleId(second.m_ruleId)
    {}

    ExtendedEffect& operator=(const ExtendedEffect &second) {
        m_effect = second.m_effect;
        m_ruleId = second.m_ruleId;
        return *this;
    }

    Effect getEffect() const { return m_effect; }

    RuleId getRuleId() const { return m_ruleId; }

private:
    Effect m_effect;
    RuleId m_ruleId;
};

typedef std::list<ExtendedEffect> ExtendedEffectList;

inline const char *toString(const ExtendedEffect &effect)
{
    const char * temp = "";

    switch (effect.getEffect()) {
    case Deny:
        temp = "Deny";
        break;
    case Undetermined:
        temp = "Undetermined";
        break;
    case PromptOneShot:
        temp = "PromptOneShot";
        break;
    case PromptSession:
        temp = "PromptSession";
        break;
    case PromptBlanket:
        temp = "PromptBlanket";
        break;
    case Permit:
        temp = "Permit";
        break;
    case Inapplicable:
        temp = "Inapplicable";
        break;
    case NotMatchingTarget:
        temp = "NotMatchingTarget";
        break;
    case Error:
        temp = "Error";
        break;
    default:;
    }
    return temp;
}

#endif  //_EFFECT_H_
