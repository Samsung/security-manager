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
#include <tuple>
#include <iostream>
#include <ostream>
#include <cynara-plugin.h>

#include <lm-config.h>

//#include <types/PolicyDescription.h>
//#include <types/SupportedTypes.h>
#include <translator.h>

//#include "CapacityCache.h"

using namespace Cynara;

//typedef std::tuple<std::string, std::string, std::string> Key;
//std::ostream &operator<<(std::ostream &os, const Key &key) {
//    os << "client: " << std::get<0>(key)
//       << ", user: " << std::get<1>(key)
//       << ", privilege: " << std::get<2>(key);
//    return os;
//}
//
//std::ostream &operator<<(std::ostream &os, const PolicyResult &result) {
//    os << "type: " << result.policyType()
//       << ", metadata: " << result.metadata();
//    return os;
//}

namespace LicenseManager {

//std::function<std::string(const Key&)> hasher = [](const Key &key) {
//    const char separator = '\1';
//    const auto &client = std::get<0>(key);
//    const auto &user = std::get<1>(key);
//    const auto &privilege = std::get<2>(key);
//    return client + user + privilege + separator +
//            std::to_string(client.size()) + separator +
//            std::to_string(user.size()) + separator +
//            std::to_string(privilege.size());
//};

const std::vector<PolicyDescription> serviceDescriptions = {
    { Config::LM_ASK, "License Manager plugin." }
};

class ServicePlugin : public ServicePluginInterface {
public:
    ServicePlugin()
//        : m_cache(hasher)
    {}
    const std::vector<PolicyDescription> &getSupportedPolicyDescr() {
        return serviceDescriptions;
    }

    PluginStatus check(const std::string &/*client*/,
                       const std::string &/*user*/,
                       const std::string &/*privilege*/,
                       PolicyResult &result,
                       AgentType &/*requiredAgent*/,
                       PluginData &/*pluginData*/) noexcept
    {
        try {
//            if (!m_cache.get(Key(client, user, privilege), result)) {
//                pluginData = Translator::requestToData(client, user, privilege);
//                requiredAgent = AgentType(Config::AgentName);
//                return PluginStatus::ANSWER_NOTREADY;
//            }
//            if (result.policyType() == SupportedTypes::Client::ALLOW_PER_LIFE)
//                result = PolicyResult(PredefinedPolicyType::ALLOW);
//            else
//                result = PolicyResult(PredefinedPolicyType::DENY);
            result = PolicyResult(Config::LM_ALLOW);
            return PluginStatus::ANSWER_READY;
        } catch (const Translator::TranslateErrorException &e) {
            LOGE("Error translating request to data : " << e.what());
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
            PolicyType resultType = Translator::dataToAnswer(agentData);
            result = PolicyResult(resultType);

//            if (resultType == Config::LM_ALLOW) {
//                m_cache.update(Key(client, user, privilege), PolicyResult(resultType));
//                result = PolicyResult(PredefinedPolicyType::ALLOW);
//            } else if (resultType == SupportedTypes::Client::DENY_PER_LIFE) {
//                m_cache.update(Key(client, user, privilege), PolicyResult(resultType));
//                result = PolicyResult(PredefinedPolicyType::DENY);
//            }

            return PluginStatus::SUCCESS;
        } catch (const Translator::TranslateErrorException &e) {
            LOGE("Error translating data to answer : " << e.what());
        } catch (const std::exception &e) {
            LOGE("Failed with std exception: " << e.what());
        } catch (...) {
            LOGE("Failed with unknown exception: ");
        }
        return PluginStatus::ERROR;
    }

    void invalidate() {
//        m_cache.clear();
    }

//private:
//    Plugin::CapacityCache<Key, PolicyResult> m_cache;
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
