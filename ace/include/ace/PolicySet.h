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
//  @ File Name : PolicySet.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#if !defined(_POLICYSET_H)
#define _POLICYSET_H

#include "Policy.h"
#include <iostream>

class PolicySet : public Policy
{
  public:

    //TODO Clean this class
    //PolicySet(CombineAlgorithm algorithm, std::list<Attribute> * targetAttr,const std::string & subjectId)
    //        : Policy(algorithm,targetAttr,subjectId)
    //    {}
    PolicySet()
    {
    }
    ~PolicySet()
    {
    }
};

#endif  //_POLICYSET_H
