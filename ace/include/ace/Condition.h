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
// File:   Condition.h
// Author: notroot
//
// Created on June 3, 2009, 9:00 AM
//
#ifndef _CONDITION_H
#define _CONDITION_H

#include <list>
#include <set>
#include <iostream>
#include <dpl/foreach.h>

#include "Attribute.h"
#include "Effect.h"
#include "TreeNode.h"

class Condition
{
  public:
    enum CombineType
    {
        AND, OR
    };

    void addCondition(const Condition & condition)
    {
        this->conditions.push_back(condition);
    }

    void addAttribute(const Attribute & attribute)
    {
        this->attributes.push_back(attribute);
    }

    void setCombineType(CombineType type)
    {
        this->combineType = type;
    }

    Condition() : combineType(AND),
        parent(NULL)
    {
    }

    Condition(CombineType type) : combineType(type),
        parent(NULL)
    {
    }

    virtual ~Condition()
    {
    }

    Condition * getParent()
    {
        return this->parent;
    }

    void setParent(Condition * condition)
    {
        this->parent = condition;
    }

    Attribute::MatchResult evaluateCondition(
            const AttributeSet * attrSet) const;

    friend std::ostream & operator<<(std::ostream & out,
            Condition & condition)
    {
        FOREACH (it, condition.attributes)
        {
            out << *it;
        }
        return out;
    }
    //[CR] change function name
    void getAttributes(AttributeSet * attrSet);

  private:
    Attribute::MatchResult evaluateChildConditions(
            const AttributeSet * attrSet,
            bool &isFinalMatch,
            bool & undefinedMatchFound) const;

    Attribute::MatchResult evaluateAttributes(
            const AttributeSet * attrSet,
            bool& isFinalMatch,
            bool & undefinedMatchFound) const;

    // KW     Attribute::MatchResult performANDalgorithm(const std::set<Attribute> * attributes) const;

    // KW     Attribute::MatchResult performORalgorithm(const std::set<Attribute> * attributes) const;

    bool isEmpty() const
    {
        return attributes.empty() && conditions.empty();
    }

    bool isAndCondition() const
    {
        return combineType == AND;
    }

    bool isOrCondition() const
    {
        return combineType == OR;
    }

    std::list<Condition> conditions;
    CombineType combineType;
    std::list<Attribute> attributes;
    Condition *parent;
};

#endif    /* _CONDITION_H */

