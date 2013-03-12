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
//  @ File Name : Policy.cpp
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#include <ace/Policy.h>

Policy::~Policy()
{
    for (std::list<const Subject *>::iterator it = subjects->begin();
         it != subjects->end();
         ++it) {
        delete *it;
    }
    delete subjects;
}

void Policy::printData()
{
    std::string subject;
    if (subjects != NULL && subjects->size()) {
        subject = (subjects->front())->getSubjectId();
    }
    std::string algorithm = printCombineAlgorithm(this->combineAlgorithm);

    std::cout << "subject: " << subject << " algorithm: " << algorithm <<
    std::endl;
}

std::string Policy::printCombineAlgorithm(CombineAlgorithm algorithm)
{
    switch (algorithm) {
    case DenyOverride:
        return "DenyOverride";
    case PermitOverride:
        return "PermitOverride";
    case FirstApplicable:
        return "FirstApplicable";
    case FirstTargetMatching:
        return "FirstTargetMatching";
    default:
        return "ERROR: Wrong Algorithm";
    }
}

const char * toString(Policy::CombineAlgorithm algorithm)
{
    switch (algorithm) {
    case Policy::DenyOverride:
        return "DenyOverride";
    case Policy::PermitOverride:
        return "PermitOverride";
    case Policy::FirstApplicable:
        return "FirstApplicable";
    case Policy::FirstTargetMatching:
        return "FirstTargetMatching";
    default:
        return "ERROR: Wrong Algorithm";
    }
}
