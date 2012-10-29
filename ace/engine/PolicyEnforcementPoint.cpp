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
 * @file    security_logic.cpp
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @author  Ming Jin(ming79.jin@samsung.com)
 * @version 1.0
 * @brief   Implementation file for security logic
 */
#include <ace/PolicyEnforcementPoint.h>

#include <sstream>
#include <algorithm>
#include <list>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cstdlib>
#include <map>

#include <dpl/assert.h>
#include <dpl/exception.h>
#include <dpl/log/log.h>

#include <ace/PolicyEvaluatorFactory.h>
#include <ace/PolicyResult.h>
#include <ace/Request.h>

PolicyEnforcementPoint::PolicyEnforcementPoint() :
    m_wrt(0),
    m_res(0),
    m_sys(0),
    m_pdp(0),
    m_pip(0)
{}

void PolicyEnforcementPoint::terminate()
{
    LogInfo("PolicyEnforcementPoint is being deinitialized.");

    delete m_sys;
    delete m_res;
    delete m_wrt;
    delete m_pdp;
    delete m_pip;
    m_sys = 0;
    m_res = 0;
    m_wrt = 0;
    m_pdp = 0;
    m_pip = 0;
}

PolicyEnforcementPoint::~PolicyEnforcementPoint()
{
    Assert((m_sys == 0) && "You must run "
           "PolicyEnforcementPoint::Deinitialize before exit program!");
}

void PolicyEnforcementPoint::initialize(
        IWebRuntime *wrt,
        IResourceInformation *resource,
        IOperationSystem *operation)
{
    if (m_wrt) {
        ThrowMsg(PEPException::AlreadyInitialized,
                 "Policy Enforcement Point is already initialzed");
    }

    m_wrt = wrt;
    m_res = resource;
    m_sys = operation;

    if (this->m_pip != NULL) {
        this->m_pip->update(m_wrt, m_res, m_sys);
        return;
    }

    this->m_pip = new PolicyInformationPoint(wrt, m_res, m_sys);
    this->m_pdp = new PolicyEvaluator(m_pip);

    if (!this->m_pdp->initPDP()) {
        Assert(0);
    }
}

ExtendedPolicyResult PolicyEnforcementPoint::check(Request &request)
{
    return m_pdp->getPolicyForRequest(request);
}

void PolicyEnforcementPoint::updatePolicy(const std::string &policy)
{
    LogDebug("ACE updatePolicy: " << policy);
    int errorCode = 0;

    if (m_pdp == NULL) {
        LogError("Evaluator not set. Ignoring message.");
        Assert(false && "UpdateClient error on receiving event");
    } else {
        LogDebug("Emitting update signal.");
        errorCode = m_pdp->updatePolicy(policy.c_str());
    }

    LogDebug("Sending reponse: " << errorCode);
}

void PolicyEnforcementPoint::updatePolicy()
{
    LogDebug("ACE updatePolicy");
    if (m_pdp == NULL) {
        LogError("Evaluator not set. Ignoring message.");
    } else {
        m_pdp->updatePolicy();
    }
}

OptionalExtendedPolicyResult PolicyEnforcementPoint::checkFromCache(Request &request)
{
   return m_pdp->getPolicyForRequestFromCache(request);
}

OptionalExtendedPolicyResult PolicyEnforcementPoint::check(Request &request,
                                                   bool fromCacheOnly)
{
   return m_pdp->getPolicyForRequest(request, fromCacheOnly);
}
