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
 * @file    security_controller.h
 # @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @author  Ming Jin(ming79.jin@samsung.com)
 * @author  Piotr Kozbial (p.kozbial@samsung.com)
 * @version 1.0
 * @brief   Header file for security logic
 */

#include <security_logic.h>
#include <attribute_facade.h>
#ifdef WRT_SMACK_ENABLED
#include <privilege-control.h>
#endif
#include <ace-dao-rw/AceDAO.h>
#include <ace-dao-ro/AceDAOConversions.h>
#include <ace/PolicyInformationPoint.h>
#include <ace/PromptDecision.h>
#include <dpl/log/log.h>

#include <dpl/wrt-dao-ro/widget_dao_read_only.h>
#include <dpl/wrt-dao-ro/WrtDatabase.h>

namespace {

Request::ApplicationType getAppType(const Request *request) {
    WrtDB::WidgetDAOReadOnly widgetDao(request->getWidgetHandle());
    WrtDB::AppType appType = widgetDao.getWidgetType().appType;
    switch (appType) {
    case WrtDB::AppType::APP_TYPE_TIZENWEBAPP:
        LogDebug("==== Found Tizen application. ====");
        return Request::APP_TYPE_TIZEN;
    case WrtDB::AppType::APP_TYPE_WAC20:
        LogDebug("==== Found Wac20 application. ====");
        return Request::APP_TYPE_WAC20;
    default:
        LogDebug("==== Unknown application type. ====");
    }
    return Request::APP_TYPE_UNKNOWN;
}

} // anonymous namespace

void SecurityLogic::initialize() {
    WrtDB::WrtDatabase::attachToThreadRO();
    m_policyEnforcementPoint.initialize(new WebRuntimeImpl(),
                                        new ResourceInformationImpl(),
                                        new OperationSystemImpl());
}

void SecurityLogic::terminate() {
    m_policyEnforcementPoint.terminate();
    WrtDB::WrtDatabase::detachFromThread();
}


void SecurityLogic::grantPlatformAccess(const Request& request)
{
    (void)request;
#ifdef WRT_SMACK_ENABLED
    try {
        unsigned long long id =
            static_cast<unsigned long long>(request.getWidgetHandle());
        Request::DeviceCapabilitySet dc = request.getDeviceCapabilitySet();

        size_t i,size = dc.size();
        std::unique_ptr<const char*[]> array(new const char*[size+1]);

        array[size] = NULL;
        auto it = dc.begin();

        for(i=0; (i<size) && (it!=dc.end()); ++i,++it) {
            array[i] = it->c_str();
        }
        int ret = wrt_permissions_add(id, array.get());
        if (PC_OPERATION_SUCCESS != ret) {
            LogError("smack rules couldn't be granted");
        }
    } catch (std::bad_alloc&) {
        LogError("smack rules couldn't be granted: memory allocation failed");
    }
#endif
}

PolicyResult SecurityLogic::checkFunctionCall(Request* request)
{
    Assert(NULL != request);

    LogDebug("=== Check widget existance ===");
    Try {
        request->setAppType(getAppType(request));
    } Catch (WrtDB::WidgetDAOReadOnly::Exception::WidgetNotExist) {
        LogError("==== Couldn't find widget for handle: " <<
            request->getWidgetHandle() << ". Access denied. ====");
        return PolicyEffect::DENY;
    }

    PolicyResult aceResult = m_policyEnforcementPoint.check(*request).policyResult;

    if (aceResult == PolicyEffect::PERMIT) {
        grantPlatformAccess(*request);
        return PolicyEffect::PERMIT;
    } else if (aceResult == PolicyEffect::PROMPT_ONESHOT ||
               aceResult == PolicyEffect::PROMPT_SESSION ||
               aceResult == PolicyEffect::PROMPT_BLANKET ||
               aceResult == PolicyDecision::NOT_APPLICABLE ||
               aceResult == PolicyResult::UNDETERMINED)
    {
        // TODO: check stored user answers!!!
        // if necessary, grant SMACK rules
        // return appropriately - the following is a dummy:
        return aceResult;
    } else {
        return PolicyEffect::DENY;
    }
}

PolicyResult SecurityLogic::checkFunctionCall(Request* request, const std::string &sessionId)
{
    Assert(NULL != request);
    LogDebug("=== Check existance of widget === ");
    Try {
        request->setAppType(getAppType(request));
    } Catch (WrtDB::WidgetDAOReadOnly::Exception::WidgetNotExist) {
        LogError("==== Couldn't find widget for handle: " <<
            request->getWidgetHandle() << ". Access denied. ====");
        return PolicyEffect::DENY;
    }

    ExtendedPolicyResult exAceResult = m_policyEnforcementPoint.check(*request);
    PolicyResult aceResult = exAceResult.policyResult;

    LogDebug("Result returned by policy " << aceResult << ". RuleID: " << exAceResult.ruleId);

    if (aceResult == PolicyEffect::PERMIT) {
        LogDebug("Grant access.");
        grantPlatformAccess(*request);
        return PolicyEffect::PERMIT;
    }

    if (aceResult == PolicyEffect::PROMPT_ONESHOT ||
        aceResult == PolicyEffect::DENY)
    {
        return aceResult;
    }

    OptionalCachedPromptDecision decision = AceDB::AceDAOReadOnly::getPromptDecision(
        request->getWidgetHandle(),
        exAceResult.ruleId);

    if (decision.IsNull()) {
        LogDebug("No CachedPromptDecision found.");
        return aceResult;
    }

    if (aceResult == PolicyEffect::PROMPT_BLANKET) {
        if (decision->decision == PromptDecision::ALLOW_ALWAYS) {
            LogDebug("Found user decision. Result changed to PERMIT. Access granted");
            grantPlatformAccess(*request);
            return PolicyEffect::PERMIT;
        }
        if (decision->decision == PromptDecision::DENY_ALWAYS) {
            LogDebug("Found user decision. Result changed to DENY.");
            return PolicyEffect::DENY;
        }
        if (decision->decision == PromptDecision::ALLOW_FOR_SESSION
            && !(decision->session.IsNull())
            && sessionId == DPL::ToUTF8String(*(decision->session)))
        {
            LogDebug("Result changed to PERMIT. Access granted.");
            grantPlatformAccess(*request);
            return PolicyEffect::PERMIT;
        }
        if (decision->decision == PromptDecision::DENY_FOR_SESSION
            && !(decision->session.IsNull())
            && sessionId == DPL::ToUTF8String(*(decision->session)))
        {
            LogDebug("Found user decision. Result changed to DENY.");
            return PolicyEffect::DENY;
        }
        return aceResult;
    }

    if (aceResult == PolicyEffect::PROMPT_SESSION) {
        if (decision->decision == PromptDecision::ALLOW_FOR_SESSION
            && !(decision->session.IsNull())
            && sessionId == DPL::ToUTF8String(*(decision->session)))
        {
            LogDebug("Found user decision. Result changed to PERMIT. Access granted.");
            grantPlatformAccess(*request);
            return PolicyEffect::PERMIT;
        }
        if (decision->decision == PromptDecision::DENY_FOR_SESSION
            && !(decision->session.IsNull())
            && sessionId == DPL::ToUTF8String(*(decision->session)))
        {
            LogDebug("Found user decision. Result changed to DENY.");
            return PolicyEffect::DENY;
        }
        return aceResult;
    }

    // This should not happend - all PolicyEffect values were supported before.
    // This mean that someone has modyfied PolicyEffect enum. SPANK SPANK SPANK
    LogError("Unsupported PolicyEffect!");
    return PolicyEffect::DENY;
}

void SecurityLogic::validatePopupResponse(Request* request,
                                          bool allowed,
                                          Prompt::Validity validity,
                                          const std::string& sessionId,
                                          bool* retValue)
{
    Assert(NULL != retValue);
    Assert(NULL != request);

    LogDebug("Start");
    LogDebug("User answered: " << allowed << " with validity: " << validity);
    LogDebug("Check widget existance");
    Try {
        request->setAppType(getAppType(request));
    } Catch (WrtDB::WidgetDAOReadOnly::Exception::WidgetNotExist) {
        LogError("==== Couldn't find widget for handle: " <<
            request->getWidgetHandle() << ". Access denied. ====");
        retValue = false;
        return;
    }

    *retValue = false;
    OptionalExtendedPolicyResult extendedAceResult =
        m_policyEnforcementPoint.checkFromCache(*request);
    if (extendedAceResult.IsNull()) {
        LogDebug("No cached policy result - but it should be here");
        LogDebug("returning " << *retValue);
        return;
    }

    PolicyResult aceResult = extendedAceResult->policyResult;
    if (aceResult == PolicyEffect::DENY) {
        LogDebug("returning " << *retValue);
        return;
    }
    if (aceResult == PolicyEffect::PERMIT) {
        // TODO  we were asked for prompt validation
        // but we got that no prompt should be opened - is this OK?
        // (this is on the diagram in wiki)
        *retValue = true;
    } else if (aceResult == PolicyEffect::PROMPT_ONESHOT ||
               aceResult == PolicyEffect::PROMPT_SESSION ||
               aceResult == PolicyEffect::PROMPT_BLANKET)
    {
        Request::DeviceCapabilitySet devCaps =
                request->getDeviceCapabilitySet();

        FOREACH (it, devCaps) {
            Request::DeviceCapability resourceId = *it;
            LogDebug("Recheck: " << *it);
            // 1) check if per-widget settings permit
            AceDB::PreferenceTypes wgtPref =
                AceDB::AceDAO::getWidgetDevCapSetting(
                    resourceId,
                    request->getWidgetHandle());
            if (AceDB::PreferenceTypes::PREFERENCE_DENY == wgtPref) {
                LogDebug("returning " << *retValue);
                return;
            }
            // 2) check if per-dev-cap settings permit
            AceDB::PreferenceTypes resPerf =
                AceDB::AceDAO::getDevCapSetting(resourceId);
            if (AceDB::PreferenceTypes::PREFERENCE_DENY == resPerf) {
                LogDebug("returning " << *retValue);
                return;
            }

            // 3) check for stored propmt answer - should not be there
            // TODO  - is this check necessary?
            AceDB::BaseAttributeSet attributes;
            AceDB::AceDAO::getAttributes(&attributes);
            Request req(request->getWidgetHandle(),
                        request->getExecutionPhase());
            req.addDeviceCapability(resourceId);
            PolicyInformationPoint *pip =
                m_policyEnforcementPoint.getPip();

            Assert(NULL != pip);

            pip->getAttributesValues(&req, &attributes);
            auto attrHash = AceDB::AceDaoConversions::convertToHash(attributes);

            // 4) validate consistency of answer with policy result
            Prompt::Validity clampedValidity =
                    clampPromptValidity(validity, *(aceResult.getEffect()));

            // 5) store answer in database if appropriate
            // TODO  how about userParam? sessionId?
            DPL::String userParam = DPL::FromUTF8String(sessionId);
            DPL::OptionalString sessionOptional =
                DPL::FromUTF8String(sessionId);

            switch (clampedValidity) {
            case Prompt::Validity::ALWAYS: {
                AceDB::AceDAO::setPromptDecision(
                    request->getWidgetHandle(),
                    extendedAceResult->ruleId,
                    sessionOptional,
                    allowed ?
                    PromptDecision::ALLOW_ALWAYS :
                    PromptDecision::DENY_ALWAYS);
                break; }
            case Prompt::Validity::SESSION: {
                AceDB::AceDAO::setPromptDecision(
                    request->getWidgetHandle(),
                    extendedAceResult->ruleId,
                    sessionOptional,
                    allowed ?
                    PromptDecision::ALLOW_FOR_SESSION :
                    PromptDecision::DENY_FOR_SESSION);
                break; }

            case Prompt::Validity::ONCE: {
                LogInfo("Validity ONCE, not saving prompt decision to cache");
                break; }
            }

        }
        // access granted!
        *retValue = allowed;
    }
    if (*retValue) {
        // 6) grant smack label if not granted yet
        grantPlatformAccess(*request);
    }
    LogDebug("Finish");
    LogDebug("returning " << *retValue);
}

void SecurityLogic::updatePolicy()
{
    LogDebug("SecurityLogic::updatePolicy");
    m_policyEnforcementPoint.updatePolicy();
}

Prompt::Validity SecurityLogic::clampPromptValidity(
        Prompt::Validity validity,
        PolicyEffect effect)
{
    switch (effect) {
    case PolicyEffect::PROMPT_BLANKET: {
        return validity; }
    case PolicyEffect::PROMPT_SESSION: {
        if (Prompt::Validity::ALWAYS == validity) {
            LogInfo("ALWAYS returned from prompt in PROMPT_SESSION");
            return Prompt::Validity::SESSION;
        }
        return validity; }
    case PolicyEffect::PROMPT_ONESHOT: {
        if (Prompt::Validity::ONCE != validity) {
            LogInfo("Not ONCE returned from prompt in PROMPT_ONESHOT");
        }
        return Prompt::Validity::ONCE; }
    case PolicyEffect::DENY:
    case PolicyEffect::PERMIT:
    default: {// other options - should not happen
        LogError("This kind of policy effect does not deal with prompts");
        return Prompt::Validity::ONCE;  }
    }
}

