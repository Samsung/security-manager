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
//  @ Project : Access Control Engine
//  @ File Name : UserDecision.h
//  @ Date : 2009-05-22
//  @ Author : Samsung
//
//

#ifndef _WIDGET_USAGE_H
#define _WIDGET_USAGE_H

#include <dpl/event/event_support.h>

#include "Request.h"
#include "AsyncVerdictResultListener.h"

enum UsageValidity
{
    USAGE_UNKNOWN,
    USAGE_ONCE,
    USAGE_SESSION,
    USAGE_ALWAYS
};

enum UsageVerdict
{
    USAGE_VERDICT_PERMIT,
    USAGE_VERDICT_DENY,
    USAGE_VERDICT_INAPPLICABLE,
    USAGE_VERDICT_UNDETERMINED,
    USAGE_VERDICT_UNKNOWN,
    USAGE_VERDICT_ERROR
};
//Forward declaration
class PolicyEvaluator;

class PolicyEvaluatorData
{
  private:
    Request m_request;
    UsageValidity m_validity;
    UsageVerdict m_verdict;
    AsyncVerdictResultListener *m_listener;
  public:

    PolicyEvaluatorData(const Request& request,
            AsyncVerdictResultListener *listener) :
        m_request(request),
        m_validity(USAGE_UNKNOWN),
        m_verdict(USAGE_VERDICT_ERROR),
        m_listener(listener)
    {
    }

    // KW     UsageValidity getValidity() const {
    // KW         return m_validity;
    // KW     }
    // KW
    // KW     UsageVerdict getVerdict() const {
    // KW         return m_verdict;
    // KW     }
    // KW
    // KW     void setValidity(UsageValidity validity) {
    // KW         this->m_validity = validity;
    // KW     }
    // KW
    // KW     void setVerdict(UsageVerdict verdict) {
    // KW         this->m_verdict = verdict;
    // KW     }

    const Request& getRequest() const
    {
        return m_request;
    }

    AsyncVerdictResultListener* getListener() const
    {
        return m_listener;
    }
};

#endif  //_USERDECISION_H
