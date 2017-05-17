/*
 *  Copyright (c) 2014-2017 Samsung Electronics Co.
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
 * @file        service.cpp
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       Implementation of cynara server side license manager plugin.
 */

#include <string>
#include <iostream>
#include <cynara-plugin.h>

#include <lm-config.h>

using namespace Cynara;

namespace LicenseManager {

const std::vector<PolicyDescription> serviceDescriptions = {
    { Config::LM_ASK, "License Manager plugin." }
};

class ServicePlugin : public ServicePluginInterface {
public:
    ServicePlugin() {}

    const std::vector<PolicyDescription> &getSupportedPolicyDescr() {
        return serviceDescriptions;
    }

    PluginStatus check(const std::string &client,
                       const std::string &user,
                       const std::string &privilege,
                       PolicyResult &/*result*/,
                       AgentType &requiredAgent,
                       PluginData &pluginData) noexcept
    {
        try {
            std::stringstream ss;
            ss << client << " " << user << " " << privilege;
            pluginData = ss.str();

            requiredAgent = Config::AgentName;

            return PluginStatus::ANSWER_NOTREADY;
        } catch (const std::exception &e) {
            LOGE("Failed with std exception: " << e.what());
        } catch (...) {
            LOGE("Failed with unknown exception: ");
        }
        return PluginStatus::ERROR;
    }

    PluginStatus update(const std::string & /*client*/,
                        const std::string & /*user*/,
                        const std::string & /*privilege*/,
                        const PluginData &agentData,
                        PolicyResult &result) noexcept
    {
        try {
            int answer;
            std::stringstream ss(agentData);
            ss >> answer;

            result = PolicyResult(answer ? Config::LM_ALLOW : Config::LM_DENY);
            return PluginStatus::SUCCESS;
        } catch (const std::exception &e) {
            LOGE("Failed with std exception: " << e.what());
        } catch (...) {
            LOGE("Failed with unknown exception: ");
        }
        return PluginStatus::ERROR;
    }

    void invalidate() {}
};

} // namespace LicenseManager

extern "C" {
ExternalPluginInterface *create(void) {
    return new LicenseManager::ServicePlugin();
}

void destroy(ExternalPluginInterface *ptr) {
    delete ptr;
}
} // extern "C"
