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
 * @file        src/license-manager/agent/agent.h
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       Implementation of main loop of the agent
 */
#pragma once

#include <cynara-agent.h>

#include <agent_logic.h>

namespace LicenseManager {

class Agent {
public:
    Agent()
      : m_logic(nullptr)
      , m_cynara(nullptr)
    {}

    Agent(const Agent &) = delete;
    Agent(Agent &&) = delete;

    Agent& operator=(const Agent &) = delete;
    Agent& operator=(Agent &&) = delete;

    bool initialize(AgentLogic *logic);
    bool mainLoop();
    void exitLoop();
    bool deinitialize();

    virtual ~Agent();

private:
    AgentLogic *m_logic;
    cynara_agent *m_cynara;
};

} // namespace LicenseManager

