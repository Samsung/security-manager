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
//  @ File Name : CombinerImpl.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#ifndef _COMBINER_IMPL_H
#define _COMBINER_IMPL_H

#include <list>
#include <dpl/log/log.h>

#include "Combiner.h"
#include "Effect.h"
#include "Policy.h"
#include "Subject.h"

class CombinerImpl : public Combiner
{
  public:

    virtual ExtendedEffect combineRules(const TreeNode * rule);
    virtual ExtendedEffect combinePolicies(const TreeNode * policy);

    virtual ~CombinerImpl()
    {
    }

  protected:

    bool checkIfTargetMatches(const std::list<const Subject *> * subjectsSet,
            bool &isUndetermined);

    ExtendedEffect combine(Policy::CombineAlgorithm algorithm,
            ExtendedEffectList &effects);

    ExtendedEffect denyOverrides(const ExtendedEffectList &effects);
    ExtendedEffect permitOverrides(const ExtendedEffectList &effects);
    ExtendedEffect firstApplicable(const ExtendedEffectList &effects);
    ExtendedEffect firstMatchingTarget(const ExtendedEffectList &effects);

    std::list<int> * convertEffectsToInts(const std::list<Effect> * effects);
    Effect convertIntToEffect(int intEffect);

    void showEffectList(ExtendedEffectList & effects)
    {
        ExtendedEffectList::iterator it = effects.begin();
        for (; it != effects.end(); ++it) {
            LogDebug(toString(*it));
        }
    }

  private:
    bool isError(const ExtendedEffectList &effects);
};

#endif  //_COMBINERIMPL_H
