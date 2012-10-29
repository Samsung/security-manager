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
// File: Condition.cpp
// Author: notroot
//
// Created on June 3, 2009, 9:00 AM
//

#include <iostream>
#include <dpl/log/log.h>
#include <dpl/foreach.h>
#include <ace/Condition.h>

/**
 * Check if attribute in condition matches the values obtained from PIP
 * attrSet - attributes from PIP
 */

Attribute::MatchResult Condition::evaluateCondition(
        const AttributeSet * attrSet) const
{
    //Condition may include either matches of attributes or other conditions
    //in this method all attributes are matched at first and if possible the
    //condition is evaluated. If evaluation is not possible based solely on
    //attributes then we start recursion into child conditions.

    Attribute::MatchResult match;
    bool undeterminedMatchFound = false;
    bool isFinalMatch = false;

    LogDebug("Attributes to be matched");
    printAttributes(*attrSet);
    LogDebug("Condition attributes values");
    printAttributes(attributes);

    if (this->isEmpty()) {
        LogDebug("Condition is empty, returning true");
        //Condition is empty, it means it evaluates to TRUE
        return Attribute::MatchResult::MRTrue;
    }

    match = evaluateAttributes(attrSet, isFinalMatch, undeterminedMatchFound);
    if (isFinalMatch) {
        LogDebug("Evaluate attributes returning verdict" ) ; //<< match);
        return match;
    }

    match = evaluateChildConditions(attrSet,
                                    isFinalMatch,
                                    undeterminedMatchFound);
    if (isFinalMatch) {
        LogDebug("Evaluate child conditions returning verdict" ); // << match);
        return match;
    }

    if (undeterminedMatchFound) {
        //If any  child condition/attribute-match was undetermined and
        //so far we couldn't make a decision then we must return undetermined
        LogDebug("Evaluate condition returning MRUndetermined");
        return Attribute::MatchResult::MRUndetermined;
    }

    if (this->isAndCondition()) {
        match = Attribute::MatchResult::MRTrue;
    } else if (this->isOrCondition()) {
        match = Attribute::MatchResult::MRFalse;
    } else {
        Assert(false && "Condition has to be either AND or OR");
    }
    return match;
}

// KW Attribute::MatchResult Condition::performORalgorithm(const std::set<Attribute>* attrSet) const{
// KW
// KW     Attribute::MatchResult match;
// KW     bool undeterminedMatchFound = false;
// KW     bool isFinalMatch = false;
// KW
// KW     LogDebug("Performing OR algorithm");
// KW
// KW     match = evaluateAttributes(attrSet, isFinalMatch, undeterminedMatchFound);
// KW     if(isFinalMatch){
// KW         LogDebug("OR algorithm evaluate attributes returning verdict" << match);
// KW         return match;
// KW     }
// KW
// KW     match = evaluateChildConditions(attrSet, isFinalMatch, undeterminedMatchFound);
// KW     if(isFinalMatch){
// KW         return match;
// KW     }
// KW
// KW     if(undeterminedMatchFound){
// KW         //If any  child condition/attribute-match was undetermined and
// KW         //so far we couldn't make a decision then we must return undetermined
// KW         LogDebug("OR algorithm returning MRUndetermined");
// KW         return Attribute::MRUndetermined;
// KW     }
// KW
// KW     LogDebug("OR algorithm returning MRFalse");
// KW     return Attribute::MRFalse;
// KW }

// KW Attribute::MatchResult Condition::performANDalgorithm(const std::set<Attribute>* attrSet) const{
// KW
// KW
// KW     Attribute::MatchResult match;
// KW     bool undeterminedMatchFound = false;
// KW     bool isFinalMatch = false;
// KW
// KW     LogDebug("Performing AND algorithm");
// KW     match = evaluateAttributes(attrSet, isFinalMatch, undeterminedMatchFound);
// KW     if(isFinalMatch){
// KW         LogDebug("AND algorithm evaluate attributes returning verdict" << match);
// KW         return match;
// KW     }
// KW     match = evaluateChildConditions(attrSet, isFinalMatch, undeterminedMatchFound);
// KW     if(isFinalMatch){
// KW         LogDebug("AND algorithm evaluate child returning verdict " << match);
// KW         return match;
// KW     }
// KW     if(undeterminedMatchFound){
// KW         //If any child condition/attribute-match was undetermined and
// KW         //so far we couldn't make a decision then we must return undetermined
// KW         LogDebug("AND algorithm returning Undetermined");
// KW         return Attribute::MRUndetermined;
// KW     }
// KW
// KW     LogDebug("AND algorithm returning MRTrue");
// KW     return Attribute::MRTrue;
// KW
// KW }

Attribute::MatchResult Condition::evaluateAttributes(
        const AttributeSet * attrSet,
        bool& isFinalMatch,
        bool & undeterminedMatchFound) const
{
    Attribute::MatchResult match = Attribute::MatchResult::MRUndetermined;

    std::list<Attribute>::const_iterator condIt = this->attributes.begin();
    while (condIt != this->attributes.end()) {
        //Find the value of needed attribute, based on attribute name
        AttributeSet::const_iterator attr =
                std::find_if(attrSet->begin(),
                             attrSet->end(),
                             AceDB::BaseAttribute::UnaryPredicate(&(*condIt)));
        if (attr == attrSet->end()) {
            LogError("Couldn't find required attribute. This should not happen");
            Assert(
                false &&
                "Couldn't find attribute required in condition. This should not happen"
                "This means that some attributes has not been obtained from PIP");
            //Return undetermined here because it seems one of the attributes is unknown/undetermined
            isFinalMatch = true;
            match = Attribute::MatchResult::MRUndetermined;
            break;
        }

        match = condIt->matchAttributes(&(*(*attr)));
        if ((match == Attribute::MatchResult::MRFalse) && isAndCondition()) {
            //FALSE match found in AND condition
            isFinalMatch = true;
            break;
        } else if ((match == Attribute::MatchResult::MRTrue) && isOrCondition()) {
            //TRUE match found in OR condition
            isFinalMatch = true;
            break;
        } else if (match == Attribute::MatchResult::MRUndetermined) {
            //Just mark that there was undetermined value found
            undeterminedMatchFound = true;
        }
        ++condIt;
    }

    return match;
}

Attribute::MatchResult Condition::evaluateChildConditions(
        const AttributeSet * attrSet,
        bool& isFinalMatch,
        bool & undefinedMatchFound) const
{
    Attribute::MatchResult match = Attribute::MatchResult::MRUndetermined;

    std::list<Condition>::const_iterator it = conditions.begin();
    while (it != conditions.end()) {
        match = it->evaluateCondition(attrSet);

        if ((match == Attribute::MatchResult::MRFalse) && isAndCondition()) {
            //FALSE match found in AND condition
            LogDebug("Child conditions results MRFalse)");
            isFinalMatch = true;
            break;
        } else if ((match == Attribute::MatchResult::MRTrue) && isOrCondition()) {
            //TRUE match found in OR condition
            LogDebug("Child conditions result MRTrue");
            isFinalMatch = true;
            break;
        } else if (match == Attribute::MatchResult::MRUndetermined) {
            undefinedMatchFound = true;
        }
        ++it;
    }

    return match;
}

void Condition::getAttributes(AttributeSet * attrSet)
{
    //Get attributes from current condition
    FOREACH (it, attributes)
    {
        AceDB::BaseAttributePtr attr(new Attribute(it->getName(), it->getMatchFunction(), it->getType()));
        attrSet->insert(attr);
    }
    //Get attributes from any child conditions
    FOREACH (it, conditions)
    {
        it->getAttributes(attrSet);
    }
}

