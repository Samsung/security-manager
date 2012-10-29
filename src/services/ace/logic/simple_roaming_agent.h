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
 * @file    simple_roaming_agent.h
 * @author  Pawel Sikorski (p.sikorski@samsung.com)
 * @author  Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version 1.0
 * @brief   simple roaming agent
 */

#ifndef WRT_SRC_ACCESS_CONTROL_COMMON_SIMPLE_ROAMING_AGENT_H_
#define WRT_SRC_ACCESS_CONTROL_COMMON_SIMPLE_ROAMING_AGENT_H_

#include <string>
#include <dpl/singleton.h>
#include <dpl/noncopyable.h>
#include <vconf.h>

class SimpleRoamingAgent : DPL::Noncopyable
{
  public:
    bool IsRoamingOn() const
    {
        return ROAMING == m_networkType;
    }

  private:
    enum NetworkType {ROAMING, HOME};

    NetworkType m_networkType;

    SimpleRoamingAgent();
    virtual ~SimpleRoamingAgent();

    static void vConfChagedCallback(keynode_t *keyNode, void *userParam);

    friend class DPL::Singleton<SimpleRoamingAgent>;
};

typedef DPL::Singleton<SimpleRoamingAgent> SimpleRoamingAgentSingleton;

#endif//WRT_SRC_ACCESS_CONTROL_COMMON_SIMPLE_ROAMING_AGENT_H_
