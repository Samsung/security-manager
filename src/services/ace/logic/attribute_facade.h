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
 * @file    attribute_facade.h
 * @author  Jaroslaw Osmanski (j.osmanski@samsung.com)
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version 1.0
 * @brief   This file contains the declaration of WebRuntimeImpl,
 *          ResourceInformationImpl, OperationSystemImpl
 */

#ifndef ATTRIBUTE_FACADE_H
#define ATTRIBUTE_FACADE_H

#include <string>
#include <map>
#include <vector>

#include <ace/WRT_INTERFACE.h>

class Request;

class WebRuntimeImpl : public IWebRuntime
{
  public:
    // Return current sessionId
    int getAttributesValuesLoop(const Request &request,
            std::list<ATTRIBUTE>* attributes,
            WidgetExecutionPhase executionPhase);

    int getAttributesValues(const Request &request,
            std::list<ATTRIBUTE>* attributes);
    virtual std::string getSessionId(const Request &request);
    WebRuntimeImpl();
};

class ResourceInformationImpl : public IResourceInformation
{
  public:
    int getAttributesValuesLoop(const Request &request,
            std::list<ATTRIBUTE>* attributes,
            WidgetExecutionPhase executionPhase);
    int getAttributesValues(const Request &request,
            std::list<ATTRIBUTE>* attributes);
    ResourceInformationImpl();
};

class OperationSystemImpl : public IOperationSystem
{
  public:
    /**
     * gather and set attributes values for specified attribute name
     * @param attributes is a list of pairs(
     *   first:   pointer to attribute name
     *   second: list of values for attribute (std::string)  -
     *   its a list of string (BONDI requirement), but usually there
     *   will be only one string
     */
    int getAttributesValues(const Request &request,
            std::list<ATTRIBUTE>* attributes);
    OperationSystemImpl();
};

class FunctionParamImpl : public IFunctionParam
{
  public:
    virtual int getAttributesValues(const Request & /*request*/,
            std::list<ATTRIBUTE> *attributes);
    void addAttribute(const std::string &key,
            const std::string &value)
    {
        paramMap.insert(make_pair(key, value));
    }
    virtual ~FunctionParamImpl()
    {
    }

  private:
    typedef std::multimap<std::string, std::string> ParamMap;
    ParamMap paramMap;
};

typedef std::vector <FunctionParamImpl> FunctionParams;

#endif //ATTRIBUTE_FACADE_H
