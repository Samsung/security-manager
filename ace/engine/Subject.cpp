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
#include <dpl/log/log.h>
#include <dpl/foreach.h>

#include <ace/Subject.h>

bool Subject::matchSubject(const AttributeSet *attrSet,
        bool &isUndetermined) const
{
    bool result = true;
    Attribute::MatchResult match = Attribute::MatchResult::MRUndetermined;

    FOREACH(it, targetAttributes)
    {
        AttributeSet::const_iterator attr =
            std::find_if(attrSet->begin(),
                         attrSet->end(),
                         AceDB::BaseAttribute::UnaryPredicate(&(*it)));
        if (attr == attrSet->end()) {
            LogError("Cannot find attribute value for " << *(it->getName()));
            Assert(false &&
                   "Attribute for subject hasn't been found."
                   "It shoud not happen. This attribute should be undetermined,"
                   "not missing");
            result = false; //According to BONDI 1.0 for signle subject all attributes must match
            isUndetermined = true;
            break;
        }

        match = it->matchAttributes(&(*(*attr)));

        if (match == Attribute::MatchResult::MRUndetermined) {
            result = false;
            isUndetermined = true;
            ///          LogError("Subject doesn match and UNDETERMINED");
            break; //According to BONDI 1.0 for signle subject all attributes must match
        } else if (match == Attribute::MatchResult::MRFalse) {
            result = false;
            //            LogError("Subject doesn match and DETERMINED");
            break; //According to BONDI 1.0 for signle subject all attributes must match
        }
    }

    return result;
}

const std::list<Attribute>& Subject::getTargetAttributes() const
{
    return targetAttributes;
}

