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
/*
 * @file    simple_roaming_agent.cpp
 * @author  Pawel Sikorski (p.sikorski@samsung.com)
 * @author  Lukasz Marek (l.marek@samsung.com)
 * @author  Lukasz Wrzosek (l.wrzosek@samsung.com)
 * @version 1.0
 * @brief   roaming agent
 */

#include "simple_roaming_agent.h"
#include <vconf.h>
#include <dpl/fast_delegate.h>
#include <dpl/log/log.h>
#include <dpl/singleton_impl.h>
IMPLEMENT_SINGLETON(SimpleRoamingAgent)

SimpleRoamingAgent::SimpleRoamingAgent()
{
    if (vconf_notify_key_changed(
            VCONFKEY_TELEPHONY_SVC_ROAM,
            vConfChagedCallback, this) < 0)
    {
        LogError("Cannot add vconf callback [" <<
                 VCONFKEY_TELEPHONY_SVC_ROAM << "]");
        Assert(false && "Cannot add vconf callback");
    }

    int result = 0;
    if (vconf_get_int(VCONFKEY_TELEPHONY_SVC_ROAM, &result) != 0) {
        LogError("Cannot get current roaming status");
        Assert(false && "Cannot get current roaming status");
    } else {
        bool type = (result == VCONFKEY_TELEPHONY_SVC_ROAM_ON);
        m_networkType = type ? ROAMING : HOME;
        LogInfo("Network type is " << (type ? "ROAMING" : "HOME"));
    }

}

SimpleRoamingAgent::~SimpleRoamingAgent()
{
    if (vconf_ignore_key_changed(
            VCONFKEY_TELEPHONY_SVC_ROAM,
            vConfChagedCallback) < 0)
    {
        LogError("Cannot rm vconf callback [" <<
                 VCONFKEY_TELEPHONY_SVC_ROAM << "]");
        Assert(false && "Cannot remove vconf callback");
    }

}

void SimpleRoamingAgent::vConfChagedCallback(keynode_t *keyNode, void *data)
{
    LogInfo("SimpleRoamingAgent::vConfChagedCallback ");
    char *key = vconf_keynode_get_name(keyNode);

    if (NULL == key) {
        LogWarning("vconf key is null.");
        return;
    }
    std::string keyString = key;
    if (VCONFKEY_TELEPHONY_SVC_ROAM != keyString) {
        LogError("Wrong key found");
        Assert(false && "Wrong key found in vconf callback");
        return;
    }
    SimpleRoamingAgent *agent = static_cast<SimpleRoamingAgent *>(data);
    if (NULL == agent) {
        LogError("Bad user arg from vconf lib");
        Assert(false && "Bad user arg from vconf lib");
        return;
    }
    int result = 0;
    if (vconf_get_int(VCONFKEY_TELEPHONY_SVC_ROAM, &result) != 0) {
        LogError("Cannot get current roaming status");
        Assert(false && "Cannot get current roaming status");
    } else {
        bool type = (result == VCONFKEY_TELEPHONY_SVC_ROAM_ON);
        agent->m_networkType = type ? ROAMING : HOME;
        LogInfo("Network type is " << (type ? "ROAMING" : "HOME"));
    }
}
