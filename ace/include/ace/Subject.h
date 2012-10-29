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
// File:   Subject.h
// Author: notroot
//
// Created on June 2, 2009, 8:47 AM
//

#ifndef _SUBJECT_H
#define    _SUBJECT_H

#include <set>
#include <list>
#include <iostream>
#include <dpl/assert.h>
#include <dpl/noncopyable.h>

#include "Attribute.h"

class Subject : DPL::Noncopyable
{
    std::string subjectId;
    std::list<Attribute> targetAttributes;

  public:
    Subject()
    {}

    const std::list<Attribute>& getTargetAttributes() const;

    void setSubjectId(const std::string & subjectId)
    {
        this->subjectId = subjectId;
    }

    //TODO maybe we should remove that becuase this causes a memory leak right now!! [CR] maybe thats true, maybe whe can remove this fun
    // KW    void setTargetAttributes(std::list<Attribute> * targetAttributes){ this->targetAttributes = targetAttributes; }

    const std::string & getSubjectId() const
    {
        return this->subjectId;
    }

    void addNewAttribute(Attribute & attr)
    {
        this->targetAttributes.push_back(attr);
    }

    //TODO in 1.0 change to true/false/undetermined
    bool matchSubject(const AttributeSet *attrSet,
            bool &isUndetermined) const;

    ~Subject()
    {}
};

#endif    /* _SUBJECT_H */

