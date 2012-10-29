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
 * @file        AbstractObjectFactory.h
 * @author      Piotr Fatyga (p.fatyga@samsung.com)
 * @version     0.1
 * @brief
 */

#ifndef _ABSTRACTOBJECTFACTORY_H
#define    _ABSTRACTOBJECTFACTORY_H

#include <ace/PolicyEvaluator.h>

class AbstractPolicyEvaluatorFactory
{
  public:
    virtual PolicyEvaluator * createPolicyEvaluator(PolicyInformationPoint *pip)
    const = 0;
};

class PolicyEvaluatorFactory : public AbstractPolicyEvaluatorFactory
{
  public:
    PolicyEvaluator * createPolicyEvaluator(PolicyInformationPoint *pip) const
    {
        return new PolicyEvaluator(pip);
    }
};

#endif    /* _ABSTRACTOBJECTFACTORY_H */

