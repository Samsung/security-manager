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
 * @file    security_controller.cpp
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @author  Ming Jin(ming79.jin@samsung.com)
 * @version 1.0
 * @brief   Implementation file for security controller
 */
#include <security_controller.h>
#include <ace/PolicyEnforcementPoint.h>
#include <ace/WRT_INTERFACE.h>
//#include <engine/PolicyEvaluatorFactory.h>
//#include <logic/attribute_facade.h>
#include <dpl/singleton_impl.h>
#include <dpl/log/log.h>
#include <security_logic.h>

IMPLEMENT_SINGLETON(SecurityController)

struct SecurityController::Impl
{
    SecurityLogic logic;
};

SecurityController::SecurityController()
{
    m_impl.Reset(new Impl);
}

SecurityController::~SecurityController()
{
}

void SecurityController::OnEventReceived(
    const SecurityControllerEvents::InitializeSyncEvent & /* event */)
{
    m_impl->logic.initialize();
}

void SecurityController::OnEventReceived(
        const SecurityControllerEvents::UpdatePolicySyncEvent& /* event */)
{
    m_impl->logic.updatePolicy();
}

void SecurityController::OnEventReceived(
    const SecurityControllerEvents::TerminateSyncEvent & /*event*/)
{
    m_impl->logic.terminate();
}

void SecurityController::OnEventReceived(
    const SecurityControllerEvents::CheckFunctionCallSyncEvent &ev)
{
    *ev.GetArg0() = m_impl->logic.checkFunctionCall(ev.GetArg1());
}

void SecurityController::OnEventReceived(
    const SecurityControllerEvents::CheckRuntimeCallSyncEvent &ev)
{
    *ev.GetArg0() = m_impl->logic.checkFunctionCall(ev.GetArg1(), ev.GetArg2());
}

void SecurityController::OnEventReceived(
	    const SecurityControllerEvents::ValidatePopupResponseEvent &ev)
{
    m_impl->logic.validatePopupResponse(ev.GetArg0(),
                                        ev.GetArg1(),
                                        ev.GetArg2(),
                                        ev.GetArg3(),
                                        ev.GetArg4());
}
