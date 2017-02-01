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
 * @file        client.cpp
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       Implementation of cynara client side license manager plugin.
 */

#include <cynara-client-plugin.h>
#include <cynara-error.h>
#include <vector>

#include <attributes/attributes.h>
#include <log/log.h>
#include <lm-config.h>

//#include <types/PolicyDescription.h>
//#include <types/SupportedTypes.h>

using namespace Cynara;

namespace LicenseManager {
const std::vector<PolicyDescription> clientDescriptions = {
        { Config::LM_ALLOW, "Allow for session" },
        { Config::LM_DENY, "Allow for session" }
};

class ClientPlugin : public ClientPluginInterface {
public:
    const std::vector<PolicyDescription> &getSupportedPolicyDescr() {
        return clientDescriptions;
    }

    bool isCacheable(const ClientSession &session UNUSED, const PolicyResult &result UNUSED) {
        return true;
    }

    bool isUsable(const ClientSession &session,
                  const ClientSession &prevSession,
                  bool &updateSession,
                  PolicyResult & /*result*/)
    {
        updateSession = false;
        return (session == prevSession);
    }

    void invalidate() {}

    virtual int toResult(const ClientSession &session UNUSED, PolicyResult &result) {
        return result.policyType() == Config::LM_ALLOW ?
            CYNARA_API_ACCESS_ALLOWED : CYNARA_API_ACCESS_DENIED;
    }
};

} // namespace LicenseManager

extern "C" {

ExternalPluginInterface *create(void) {
    return new LicenseManager::ClientPlugin();
}

void destroy(ExternalPluginInterface *ptr) {
    delete ptr;
}

} // extern "C"
