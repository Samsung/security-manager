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
//  @ File Name : CombinerImpl.cpp
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#include <dpl/log/log.h>
#include <dpl/assert.h>
#include <dpl/foreach.h>

#include <ace/CombinerImpl.h>
#include <ace/Rule.h>
#include <ace/Policy.h>

namespace {

bool denyOverridesPredecessor(
    const ExtendedEffect &first,
    const ExtendedEffect &second)
{
    if (first.getEffect() == second.getEffect())
        return first.getRuleId() < second.getRuleId();
    return first.getEffect() < second.getEffect();
}

bool permitOverridePredecessor(
    const ExtendedEffect &first,
    const ExtendedEffect &second)
{
    if (first.getEffect() == second.getEffect())
        return first.getRuleId() < second.getRuleId();
    return first.getEffect() > second.getEffect();
}

} //anonymous namespace

ExtendedEffect CombinerImpl::denyOverrides(const ExtendedEffectList &effects)
{
    if (isError(effects)) {
        return Error;
    }

    ExtendedEffect result(Inapplicable);

    FOREACH(it, effects) {
        if (denyOverridesPredecessor(*it, result)) {
            result = *it;
        }
    }
    return result;
}

ExtendedEffect CombinerImpl::permitOverrides(const ExtendedEffectList &effects)
{
    if (isError(effects)) {
        return Error;
    }

    // This magic number must be bigger that the bigest ruleId number from policy file.
    ExtendedEffect result(Deny, 999999);

    //Flag used to indicate that any of Deny,prompt-*,permit options appear
    //Consequently if flag is true then result should be return, otherwise inapplicable should be returned
    bool flag = false;
    bool flagUndetermined = false;

    FOREACH(it,effects) {
        ExtendedEffect effect = *it;

        if (effect.getEffect() == Permit) {
            return effect;
        } // no need for further check if "permit" found
        if (effect.getEffect() == Undetermined) {
            flagUndetermined = true;
        } //check for undetermined

        //Set the flag and the result even if effect is equal to result
        //It is done to mark if any "Deny" effect occured
        if (permitOverridePredecessor(effect, result)
            && effect.getEffect() != Inapplicable
            && effect.getEffect() != Undetermined)
        {
            result = effect;
            flag = true;
        }
    }

    if (flagUndetermined) {
        return ExtendedEffect(Undetermined);
    }

    if (!flag) {
        return ExtendedEffect(Inapplicable);
    }
    return result;
}

ExtendedEffect CombinerImpl::firstApplicable(
    const ExtendedEffectList & effects)
{
  if (isError(effects)) {
      return Error;
  }

  FOREACH(it,effects) {
      if (it->getEffect() != Inapplicable) {
          return *it;
      }
  }
  return Inapplicable;
}

ExtendedEffect CombinerImpl::firstMatchingTarget(
    const ExtendedEffectList &effects)
{
    if (isError(effects)) {
        return Error;
    }
    // effect list constains result of policies which target has been matched.
    //
    // If target does not match policy result is NotMatchingTarget
    // NotMatchingTarget values are not stored on the effects list
    // (you can check it in combinePolicies function).
    //
    // So we are intrested in first value on the list.
    return effects.empty() ? Inapplicable : effects.front();
}

bool CombinerImpl::isError(const ExtendedEffectList &effects)
{
    FOREACH(it, effects)
    {
        if (Error == it->getEffect()) {
            return true;
        }
    }
    return false;
}

ExtendedEffect CombinerImpl::combineRules(const TreeNode * policy)
{
    const Policy * policyObj = dynamic_cast<const Policy *>(policy->getElement());
    if (!policyObj) {
        LogError("dynamic_cast failed. PolicyObj is null.");
        return Error;
    }

    Policy::CombineAlgorithm algorithm = policyObj->getCombineAlgorithm();

    Assert(
        algorithm != Policy::FirstTargetMatching &&
        "Policy cannot have algorithm first target matching");

    bool isUndetermined = false;

    if (!checkIfTargetMatches(policyObj->getSubjects(), isUndetermined)) {
        if (isUndetermined) {
            //TODO Target is undetermined what should we do now ??
            //Right now simply return NotMatchingTarget
        }
        //Target doesn't match
        return NotMatchingTarget;
    }
    //Get all rules
    const ChildrenSet & children = policy->getChildrenSet();
    ChildrenConstIterator it = children.begin();
    ExtendedEffectList effects;

    while (it != children.end()) {
        const Rule * rule = dynamic_cast<const Rule *>((*it)->getElement());

        if (!rule) {
            LogError("Error in dynamic_cast. rule is null");
            return ExtendedEffect(Error);
        }

        ExtendedEffect effect = rule->evaluateRule(this->getAttributeSet());
        effects.push_back(effect);
        if (algorithm == Policy::FirstApplicable && effect.getEffect() != Inapplicable) {
            //For first applicable algorithm we may stop after evaluating first policy
            //which has effect other than inapplicable
            break;
        }
        ++it;
    } //end policy children iteration

    //Use combining algorithm
    ExtendedEffect ef = combine(policyObj->getCombineAlgorithm(), effects);
    return ef;
}

//WARNING this method makes an assumption that Policy target is a policy child
ExtendedEffect CombinerImpl::combinePolicies(const TreeNode * policy)
{
    const Policy * policySet = dynamic_cast<const Policy *>(policy->getElement());

    if (!policySet) {
        LogError("dynamic_cast failed. Policy set is null.");
        return Error;
    }

    bool isUndetermined = false;
    Policy::CombineAlgorithm algorithm = policySet->getCombineAlgorithm();

    if (!checkIfTargetMatches(policySet->getSubjects(), isUndetermined)) {
        /*   I can't explain this...
        if (isUndetermined) {
            if (algorithm == Policy::FirstTargetMatching) {
                return Undetermined;
            }
        }
        */
        //Target doesn't match
        return NotMatchingTarget;
    }

    const ChildrenSet & children = policy->getChildrenSet();

    ExtendedEffectList effects;

    FOREACH(it, children) {
        ExtendedEffect effect;

        if ((*it)->getTypeID() == TreeNode::PolicySet) {
            effect = combinePolicies(*it);
            if (effect.getEffect() != NotMatchingTarget) {
                effects.push_back(effect);
            }
        } else if ((*it)->getTypeID() == TreeNode::Policy) {
            effect = combineRules(*it);
            if (effect.getEffect() != NotMatchingTarget) {
                effects.push_back(effect);
            }
        } else {
            // [CR] fix it
            LogError("effect value is not initialized!");
            return ExtendedEffect(Error);
        }

        if (algorithm == Policy::FirstTargetMatching
            && effect.getEffect() != NotMatchingTarget)
        {
            //In First matching target algorithm we may return when first result is found
            break;
        }
    }

    //Use combining algorithm
    return combine(policySet->getCombineAlgorithm(), effects);
}

ExtendedEffect CombinerImpl::combine(
    Policy::CombineAlgorithm algorithm,
    ExtendedEffectList &effects)
{
    LogDebug("Effects to be combined with algorithm: " << ::toString(algorithm));
    showEffectList(effects);

    switch (algorithm) {
    case Policy::DenyOverride:
        return denyOverrides(effects);
        break;
    case Policy::PermitOverride:
        return permitOverrides(effects);
        break;
    case Policy::FirstApplicable:
        return firstApplicable(effects);
        break;
    case Policy::FirstTargetMatching:
        return firstMatchingTarget(effects);
        break;
    default:
        Assert(false && "Wrong combining algorithm used");
        return Error;
    }
}

/**
 *
 * @param attrSet set of Subject attributes in policy that identifies target
 * @return true if target  is determined and matches, false and isUndertmined is set to true if the target is undetermined
 * false and isUndetermined set to false if target is determined but doesn't match
 */
bool CombinerImpl::checkIfTargetMatches(
        const std::list<const Subject *> * subjectsList,
        bool &isUndetermined)
{
    if (subjectsList->empty()) {
        return true;
    }

    std::list<const Subject *>::const_iterator it = subjectsList->begin();
    bool match = false;
    //According to BONDI 1.0 at least one target must match
    while (it != subjectsList->end()) {
        match = (*it)->matchSubject(this->getAttributeSet(), isUndetermined);
        if (match) { //at least one match
            break;
        }
        ++it;
    }

    #ifdef _DEBUG
    if (match == Attribute::MRTrue) {
        LogDebug("Target matches ");
    } else if (match == Attribute::MRUndetermined) {
        LogDebug("Target match undetermined ");
    } else {
        LogDebug("Target doesn't match");
    }
    #endif
    return match;
}

