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
//  @ File Name : Policy.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#if !defined(_POLICY_H)
#define _POLICY_H

#include <list>

#include <ace/AbstractTreeElement.h>
#include <ace/Effect.h>
#include <ace/Attribute.h>
#include <ace/Subject.h>
#include <iostream>
#include <dpl/noncopyable.h>

class Policy : public AbstractTreeElement,
    DPL::Noncopyable
{
  public:
    enum CombineAlgorithm { DenyOverride, PermitOverride, FirstApplicable,
                            FirstTargetMatching };

    Policy()
    {
        combineAlgorithm = DenyOverride;
        subjects = new std::list<const Subject *>();
    }

    CombineAlgorithm getCombineAlgorithm() const
    {
        return this->combineAlgorithm;
    }

    void setCombineAlgorithm(CombineAlgorithm algorithm)
    {
        this->combineAlgorithm = algorithm;
    }

    const std::list<const Subject *> * getSubjects() const
    {
        return this->subjects;
    }

    void addSubject(const Subject * subject)
    {
        if (this->subjects == NULL) {
            return;
        }
        this->subjects->push_back(subject);
    }

    virtual ~Policy();

    void printData();

    std::string printCombineAlgorithm(CombineAlgorithm algorithm);

  private:
    std::list<const Subject *> *subjects;
    CombineAlgorithm combineAlgorithm;
};

const char * toString(Policy::CombineAlgorithm algorithm);

#endif  //_POLICY_H
