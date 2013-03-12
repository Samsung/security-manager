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
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @author  Ming Jin(ming79.jin@samsung.com)
 * @author  Piotr Kozbial (p.kozbial@samsung.com)
 * @version 1.0
 * @brief   Header file for security logic
 */
#ifndef SECURITY_LOGIC_H
#define SECURITY_LOGIC_H

#include <ace/Request.h>
#include <ace/PolicyResult.h>
#include <ace/AbstractPolicyEnforcementPoint.h>
#include <ace/Preference.h>
#include <ace/PolicyEnforcementPoint.h>
#include <ace-dao-ro/PromptModel.h>

/* SecurityLogic
 * May only be created and used by SecurityController.
 * There may be only one instance.
 */
class SecurityLogic {
  public:
    SecurityLogic() {}
    ~SecurityLogic() {}
    // initialize/terminate
    /** */
    void initialize();
    /** */
    void terminate();

    /** */
    PolicyResult checkFunctionCall(Request*);
    PolicyResult checkFunctionCall(Request*, const std::string &session);

    void validatePopupResponse(Request* request,
                               bool allowed,
                               Prompt::Validity validity,
                               const std::string& sessionId,
                               bool* retValue);

    /**
     * Updates policy and clears policy cache
     */
    void updatePolicy();

  private:
    PolicyEnforcementPoint m_policyEnforcementPoint;

    Prompt::Validity clampPromptValidity(Prompt::Validity validity,
                                         PolicyEffect effect);
    void grantPlatformAccess(const Request& request);
};

#endif // SECURITY_CONTROLLER_H
