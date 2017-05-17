/*
 *  Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/**
 * @file        src/license-manager/agent/agent.cpp
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       Implementation of main loop of the license manager agent
 */
#include <lm-config.h>

#include <alog.h>
#include <agent.h>

namespace LicenseManager {

bool Agent::initialize(AgentLogic *logic) {
    if (m_logic || m_cynara)
        return false;

    m_logic = logic;

    if (!m_cynara) {
        return CYNARA_API_SUCCESS == cynara_agent_initialize(&m_cynara, Config::AgentName);
    }
    return false;
}

void Agent::exitLoop() {
    cynara_agent_cancel_waiting(m_cynara);
}

bool Agent::mainLoop() {
    if (!m_cynara || !m_logic)
        return false;

    cynara_agent_msg_type reqType;
    cynara_agent_req_id reqId;
    size_t dataSize = 0;
    void *data = nullptr;

    ALOGD("Waiting for request");
    while (CYNARA_API_SUCCESS == cynara_agent_get_request(m_cynara, &reqType, &reqId, &data, &dataSize))
    {
        ALOGD("Request received ....");
        // Too late, all request are processed immediately
        if (CYNARA_MSG_TYPE_CANCEL == reqType) {
            ALOGD("Request for canceling. Ignored...");
            continue;
        }

        std::string request;
        if (data) {
            request = std::string(static_cast<char*>(data), dataSize);
        }

        ALOGD("LICENSE_MANAGER cynara_agent_put_response.");
        std::string response = m_logic->process(request);
        int ret = cynara_agent_put_response(
                m_cynara,
                CYNARA_MSG_TYPE_ACTION,
                reqId,
                response.data(),
                response.size());

        if (CYNARA_API_SUCCESS != ret)
            return false;
    }
    return true;
}

bool Agent::deinitialize() {
    if (!m_cynara && !m_logic)
        return false;

    delete m_logic;
    m_logic = nullptr;

    if (m_cynara) {
        if (CYNARA_API_SUCCESS == cynara_agent_finish(m_cynara)) {
            m_cynara = nullptr;
        } else {
            return false;
        }
    }

    return true;
}

Agent::~Agent() {
    deinitialize();
}

} // namespace LicenseManager

