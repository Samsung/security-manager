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
 * This class simply redirects the access requests to access control engine.
 * The aim is to hide access control engine specific details from WRT modules.
 * It also implements WRT_INTERFACE.h interfaces, so that ACE could access
 * WRT specific and other information during the decision making.
 *
 * @file    security_logic.h
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @author  Ming Jin(ming79.jin@samsung.com)
 * @brief   Implementation file for security logic
 */
#ifndef POLICY_ENFORCEMENT_POINT_H
#define POLICY_ENFORCEMENT_POINT_H

#include <memory>
#include <string>
#include <map>

//#include <glib/gthread.h>
//#include <glib/gerror.h>
//#include <glib.h>

//#include <dpl/optional.h>
#include <dpl/event/inter_context_delegate.h>
#include <dpl/event/property.h>

#include <ace/AbstractPolicyEnforcementPoint.h>
#include <ace/PolicyResult.h>

// Forwards
class IWebRuntime;
class IResourceInformation;
class IOperationSystem;
class PolicyEvaluator;
class PolicyInformationPoint;
class Request;

class PolicyEnforcementPoint : public AbstractPolicyEnforcementPoint
{
  public:
    OptionalExtendedPolicyResult checkFromCache(Request &request);
    ExtendedPolicyResult check(Request &request);
    OptionalExtendedPolicyResult check(Request &request,
                               bool fromCacheOnly);

    virtual ~PolicyEnforcementPoint();

    class PEPException
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, AlreadyInitialized)
    };

    /**
     * This function take ownership of objects pass in call.
     * Object will be deleted after call Deinitialize function.
     */
    void initialize(IWebRuntime *wrt,
                    IResourceInformation *resource,
                    IOperationSystem *operation);
    void terminate();

    void updatePolicy(const std::string &policy);
    void updatePolicy();

    PolicyEvaluator *getPdp() const { return this->m_pdp; }
    PolicyInformationPoint *getPip() const { return this->m_pip; }

  protected:
    PolicyEnforcementPoint();
    friend class SecurityLogic;
  private: // private data
    IWebRuntime                     *m_wrt;
    IResourceInformation            *m_res;
    IOperationSystem                *m_sys;
    PolicyEvaluator                 *m_pdp;
    PolicyInformationPoint          *m_pip;
};

#endif // POLICY_ENFORCEMENT_POINT_H
