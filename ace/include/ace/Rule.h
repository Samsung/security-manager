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
//  @ File Name : Rule.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#if !defined(_RULE_H)
#define _RULE_H

#include "Attribute.h"
#include "Effect.h"
#include "Condition.h"
#include <dpl/assert.h>

class Rule : public AbstractTreeElement
{
  public:

    ExtendedEffect evaluateRule(const AttributeSet * attrSet) const;

    Rule()
      : effect(Inapplicable)
    {
        //TODO we should set it to deny or smth, not inapplicable
    }

    void setEffect(ExtendedEffect effect)
    {
        //We should not allow to set "Inapplicable" effect.
        //Rules cannot have effect that is inapplicable, evaluation of the rules may however
        //render the effect inapplicable.
        Assert(effect.getEffect() != Inapplicable);
        this->effect = effect;
    }
    void setCondition(Condition condition)
    {
        this->condition = condition;
    }
    void getAttributes(AttributeSet * attrSet)
    {
        condition.getAttributes(attrSet);
    }

    //DEBUG methods
    std::string printEffect(const ExtendedEffect &effect) const;
    void printData();

  private:

    ExtendedEffect effect;
    Condition condition;
};

#endif  //_RULE_H
