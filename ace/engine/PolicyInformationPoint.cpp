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
//
//  @ Project : Access Control Engine
//  @ File Name : PolicyInformationPoint.cpp
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//
#include <map>
#include <string>
#include <list>

#include <ace/PolicyInformationPoint.h>
#include <ace/ConfigurationManager.h>

#include <dpl/log/log.h>
#include <dpl/assert.h>
#include <dpl/foreach.h>

#include <ace/Attribute.h>
#include <ace-dao-ro/BaseAttribute.h>
#include <ace-dao-ro/AceDAOReadOnly.h>

using namespace AceDB;

PolicyInformationPoint::PolicyInformationPoint(IWebRuntime *wrt,
        IResourceInformation *resource,
        IOperationSystem *system) : wrtInterface(wrt),
    resourceInformation(resource),
    operationSystem(system)
{
    AceDB::AceDAOReadOnly::attachToThreadRO();
}

PolicyInformationPoint::~PolicyInformationPoint()
{
    AceDB::AceDAOReadOnly::detachFromThread();
}

/* gather attributes values from adequate interfaces */
PipResponse PolicyInformationPoint::getAttributesValues(const Request* request,
        AttributeSet* attributes)
{
    int subjectReturn = 0;
    int resourceReturn = 0;
    int operationReturn = 0;
    int functionReturn = 0;
    /* create query lists  */
    createQueries(attributes);

    /* check if subject attributes query has any elements*/
    if (!subjectAttributesQuery.empty()) {
        /* get Subject Attributes */
        subjectReturn = wrtInterface->getAttributesValues(
                *request,
                &subjectAttributesQuery);
    }

    AttributeSet::const_iterator iter2;
    FOREACH(iter, subjectAttributesQuery)
    {
        if (iter->second == NULL) {
            Attribute attr(*(iter->first));
            attr.setType(Attribute::Type::Subject);
            iter2 = std::find_if(attributes->begin(),
                                 attributes->end(),
                                 BaseAttribute::UnaryPredicate(&attr));
            Assert(iter2 != attributes->end() && "This should not happen, "
                   "the attribute MUST be in attribute set");
            (*iter2)->setUndetermind(true);
        }
    }

    /* check if resource  attributes query has any elements*/
    if (!resourceAttributesQuery.empty()) {
        /* get Resource Attributes */
        resourceReturn = resourceInformation->getAttributesValues(
                *request,
                &resourceAttributesQuery);
        /* error analyzys*/
        resourceReturn <<= ERROR_SHIFT_RESOURCE;
    }

    FOREACH(iter, resourceAttributesQuery)
    {
        if (iter->second == NULL) {
            LogInfo("Found undetermined attribute");
            Attribute attr(*(iter->first));
            attr.setType(Attribute::Type::Resource);
            iter2 = std::find_if(attributes->begin(),
                                 attributes->end(),
                                 BaseAttribute::UnaryPredicate(&attr));
            Assert(iter2 != attributes->end() && "This should not happen, "
                   "the attribute MUST be in attribute set");
            (*iter2)->setUndetermind(true);
        }
    }

    /* check if resource  attributes query has any elements*/
    if (!environmentAttributesQuery.empty()) {
        /* get enviroment attributes  */
        operationReturn = operationSystem->getAttributesValues(
                *request,
                &environmentAttributesQuery);
        /* error analyzys*/
        operationReturn <<= ERROR_SHIFT_OS;
    }

    FOREACH(iter, environmentAttributesQuery)
    {
        if (iter->second == NULL) {
            //it doesnt change uniqueness of a set element so we can const_cast
            Attribute attr(*(iter->first));
            attr.setType(Attribute::Type::Environment);
            iter2 = find_if(attributes->begin(),
                            attributes->end(),
                            BaseAttribute::UnaryPredicate(&attr));
            Assert(iter2 != attributes->end() && "This should not happen, "
                   "the attribute MUST be in attribute set");
            (*iter2)->setUndetermind(true);
        }
    }

    /* check if functionParam attributes query has any elements*/
    if (!functionParamAttributesQuery.empty() && request->getFunctionParam()) {
        /* get params attributes  */
        functionReturn = request->getFunctionParam()->getAttributesValues(
                *request,
                &functionParamAttributesQuery);
        /* error analyzys*/
        functionReturn <<= ERROR_SHIFT_FP;
    }

    FOREACH(iter, functionParamAttributesQuery)
    {
        if (iter->second == NULL) {
            //it doesnt change uniqueness of a set element so we can const_cast
            Attribute attr(*(iter->first));
            attr.setType(Attribute::Type::FunctionParam);
            iter2 = find_if(attributes->begin(),
                            attributes->end(),
                            BaseAttribute::UnaryPredicate(&attr));
            Assert(iter2 != attributes->end() && "This should not happen, "
                   "the attribute MUST be in attribute set");
            (*iter2)->setUndetermind(true);
        }
    }

    // Here we must add to attributes proper marking of policy type
    // (Tizen or WAC widget)
    /**
     * This part of code seems odd here, but we don't want to keep it in
     * attribute fascade, as it is maintained by ACE clients and we are not
     * sure if this kind of distinction between different policies will be ok
     * as final solution.
     *
     * This is somehow private part of ACE, so it may be moved into
     * separate ACEAttributeFascade kind of a class in (already planned)
     * refactoring, when moving to new, C-only API for ACE.
     */
    if (widgetParamAttributesQuery.empty()) {
        LogError("No attrbutes of WidgetParam type present - "
                 "should be widget type at least");
    } else {
        LogDebug("WidgetParam type atributes present, searching for widget type");
        FOREACH(iter, widgetParamAttributesQuery) {
            const std::string *name = iter->first;
            if (POLICY_WIDGET_TYPE_ATTRIBUTE_NAME == *name) {
                LogDebug("Widget type attribute found");

                // Extracting widget type
                std::list<std::string> attrValue;
                Try {
                    AceDB::AppTypes appType =
                        AceDB::AceDAOReadOnly::getWidgetType(
                            request->getWidgetHandle());
                    switch (appType) {
                    case AceDB::AppTypes::Tizen : {
                        attrValue.push_back(POLICY_NAME_TIZEN);
                        LogDebug("==== Using Tizen policy in PIP ====");
                        break;}
                    case AceDB::AppTypes::WAC20 : {
                        attrValue.push_back(POLICY_NAME_WAC2_0);
                        LogDebug("==== Using WAC policy in PIP ====");
                        break;}
                    default: {
                        LogError("Invalid widget type");
                        }
                    }
                } Catch (AceDB::AceDAOReadOnly::Exception::DatabaseError)
                {
                    LogError("Couldn't find widget for handle "
                             << request->getWidgetHandle());
                }

                // Setting real attribute value
                Attribute attr(*(iter->first));
                attr.setType(Attribute::Type::WidgetParam);
                iter2 = find_if(attributes->begin(),
                                attributes->end(),
                                BaseAttribute::UnaryPredicate(&attr));
                Assert(iter2 != attributes->end() && "This should not happen, "
                       "the attribute MUST be in attribute set");
                (*iter2)->setUndetermind(false);
                (*iter2)->setValue(attrValue);
            }
        }
    }

    /** clear query lists*/
    resourceAttributesQuery.clear();
    environmentAttributesQuery.clear();
    subjectAttributesQuery.clear();
    functionParamAttributesQuery.clear();
    widgetParamAttributesQuery.clear();

    return subjectReturn | resourceReturn | operationReturn | functionReturn;
}

/** create query lists */
void PolicyInformationPoint::createQueries(AttributeSet* attributes)
{
    AttributeSet::const_iterator it;

    enum Attribute::Type type;

    /**iterate  all attributes and split them into adequate query  */
    FOREACH (it, *attributes) {
        type = (*it)->getType();

        switch (type) {
        case Attribute::Type::Subject:
            subjectAttributesQuery.push_back(ATTRIBUTE((*it)->getName(),
                                                       (*it)->getValue()));
            break;

        case Attribute::Type::Environment:
            environmentAttributesQuery.push_back(ATTRIBUTE((*it)->getName(),
                                                           (*it)->getValue()));
            break;

        case Attribute::Type::Resource:
            resourceAttributesQuery.push_back(ATTRIBUTE((*it)->getName(),
                                                        (*it)->getValue()));
            break;

        case Attribute::Type::FunctionParam:
            functionParamAttributesQuery.push_back(ATTRIBUTE((*it)->getName(),
                                                             (*it)->getValue()));
            break;

        case Attribute::Type::WidgetParam:
            widgetParamAttributesQuery.push_back(ATTRIBUTE((*it)->getName(),
                                                         (*it)->getValue()));
            break;
        default:
            break;
        }
    }
}

