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
#ifndef _WRT_INERFACE_4_ACE_EXAMPLE_H_
#define _WRT_INERFACE_4_ACE_EXAMPLE_H_

#include <list>
#include <map>
#include <string>

typedef int WidgetHandle;

class Request;

enum WidgetExecutionPhase
{
    WidgetExecutionPhase_Unknown           = 0,
    WidgetExecutionPhase_WidgetInstall     = 1 << 0,
    WidgetExecutionPhase_WidgetInstantiate = 1 << 1,
    WidgetExecutionPhase_WebkitBind        = 1 << 2,
    WidgetExecutionPhase_Invoke            = 1 << 3
};

struct RequestContext
{
    const WidgetHandle Handle;
    WidgetExecutionPhase Phase;

    RequestContext(WidgetHandle handle,
            WidgetExecutionPhase phase) :
        Handle(handle),
        Phase(phase)
    {
    }
};

// Pair of pointer to attribute name and pointer to list of value for
// this attribute name
typedef std::pair< const std::string* const, std::list<std::string>* >
ATTRIBUTE;

/*
 * Each function should return 0 as success and positive value as error
 *
 * Possible return value:
 * 0 - succes
 * 1 - subjectId/resourceId name unknown
 * 2 - unknown attribute name
 * 4 - interface error
 **/

/************** Web Runtime ********************/

class IWebRuntime
{
  public:

    /**
     * gather and set attributes values for specified subjectId
     * and attribute name
     * @param subjectId is a name of subject (widget or internet site URI )
     * @param attributes is a list of pairs(
     *   first:   pointer to attribute name
     *   second: list of values for attribute (std::string)   -
     *   its a list of string (BONDI requirement), but usually there will
     *   be only one string
     * */
    virtual int getAttributesValues(const Request &request,
            std::list<ATTRIBUTE> *attributes) = 0;

    /*return current sessionId */
    virtual std::string getSessionId(const Request &request) = 0;

    virtual ~IWebRuntime()
    {
    }
};

/************** Resource Information ********************/
class IResourceInformation
{
  public:
    /**
     * gather and set attributes values for specified resourceId
     * and attribute name
     * @param resourceId is a name of subject (widget or internet site URI )
     * @param attributes is a list of pairs(
     *   first:   pointer to attribute name
     *   second: list of values for attribute (std::string)  -
     *   its a list of string (BONDI requirement), but usually there will
     *   be only one string
     * */
    virtual int getAttributesValues(const Request &request,
            std::list<ATTRIBUTE> *attributes) = 0;

    virtual ~IResourceInformation()
    {
    }
};

/**************  Operation System  ********************/
class IOperationSystem
{
  public:

    /**
     * gather and set attributes values for specified attribute name
     * @param attributes is a list of pairs(
     *   first:   pointer to attribute name
     *   second: list of values for attribute (std::string)  -
     *   its a list of string (BONDI requirement), but usually
     *   there will be only one string
     * */
    virtual int getAttributesValues(const Request &request,
            std::list<ATTRIBUTE> *attributes) = 0;

    virtual ~IOperationSystem()
    {
    }
};

class IFunctionParam
{
  public:
    virtual int getAttributesValues(const Request &request,
            std::list<ATTRIBUTE> *attributes) = 0;
    virtual ~IFunctionParam()
    {
    }
};

#endif //_WRT_INERFACE_4_ACE_EXAMPLE_H_
