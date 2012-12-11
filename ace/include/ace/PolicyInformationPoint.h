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
//  @ File Name : PolicyInformationPoint.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#ifndef _POLICY_INFORMATION_POINT_H
#define _POLICY_INFORMATION_POINT_H

#include <set>

#include <ace/Attribute.h>
#include <ace/Request.h>
#include <ace/WRT_INTERFACE.h>
#include <ace-dao-ro/BaseAttribute.h>
#include <dpl/noncopyable.h>

typedef int PipResponse;

class PolicyInformationPoint : public DPL::Noncopyable
{
  private:

    /** queries for interfaces*/
    std::list<ATTRIBUTE> resourceAttributesQuery;
    std::list<ATTRIBUTE> environmentAttributesQuery;
    std::list<ATTRIBUTE> subjectAttributesQuery;
    std::list<ATTRIBUTE> functionParamAttributesQuery;
    std::list<ATTRIBUTE> widgetParamAttributesQuery;

    /** create queries */
    void createQueries(AttributeSet* attributes);

    IWebRuntime* wrtInterface;
    IResourceInformation* resourceInformation;
    IOperationSystem* operationSystem;

  public:
    static const int ERROR_SHIFT_RESOURCE = 3;
    static const int ERROR_SHIFT_OS = 6;
    static const int ERROR_SHIFT_FP = 9;

    /** Mask used to identify PIP error */
    enum ResponseTypeMask
    {
        SUCCESS               = 0,
        /* WebRuntime Error */
        WRT_UNKNOWN_SUBJECT   = 1 << 0,
        WRT_UNKNOWN_ATTRIBUTE = 1 << 1,
        WRT_INTERNAL_ERROR    = 1 << 2,
        /* Resource Information Storage Error */
        RIS_UNKNOWN_RESOURCE  = 1 << 3,
        RIS_UNKNOWN_ATTRIBUTE = 1 << 4,
        RIS_INTERNAL_ERROR    = 1 << 5,
        /*Operating system */
        OS_UNKNOWN_ATTRIBUTE  = 1 << 6,
        OS_INTERNAL_ERROR     = 1 << 7
    };

    //TODO add checking values of attributes
    /** gather attributes values from adequate interfaces */
    virtual PipResponse getAttributesValues(const Request* request,
            AttributeSet* attributes);
    virtual ~PolicyInformationPoint();
    PolicyInformationPoint(IWebRuntime *wrt,
            IResourceInformation *resource,
            IOperationSystem *system);
    virtual void update(IWebRuntime *wrt,
            IResourceInformation *resource,
            IOperationSystem *system)
    {
        wrtInterface = wrt;
        resourceInformation = resource;
        operationSystem = system;
    }
    IWebRuntime * getWebRuntime()
    {
        return wrtInterface;
    }
};

#endif  //_POLICY_INFORMATION_POINT_H
