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
 * @file        src/license-manager/agent/main.cpp
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       Main function of license manager agent
 */

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <exception>

#include <systemd/sd-daemon.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>

#include <alog.h>
#include <agent_logic.h>
#include <agent.h>

static LicenseManager::Agent *s_agentPtr = nullptr;

void kill_handler(int sig UNUSED) {
    ALOGD("License manager service is going down now");
    if (s_agentPtr)
        s_agentPtr->exitLoop();
}

int main(int, char **) {
    init_agent_log();

    int ret;
    struct sigaction act;

    memset(&act, 0, sizeof(act));
    act.sa_handler = &kill_handler;
    if ((ret = sigaction(SIGTERM, &act, NULL)) < 0) {
        ALOGE("sigaction failed [<<" << ret << "]");
        return EXIT_FAILURE;
    }

    OpenSSL_add_all_algorithms();
    SSL_library_init();
    OPENSSL_config(NULL);
    SSL_load_error_strings();

    try {

        LicenseManager::AgentLogic *logic = new LicenseManager::AgentLogic;
        LicenseManager::Agent agent;
        if (!agent.initialize(logic)) {
            ALOGE("cynara initialization failed");
            return -1;
        }
        s_agentPtr = &agent;
        ret = sd_notify(0, "READY=1");
        if (ret == 0) {
            ALOGW("Agent was not configured to notify its status");
        } else if (ret < 0) {
            ALOGE("sd_notify failed: [" << ret << "]");
        }
        agent.mainLoop();
        s_agentPtr = nullptr;
    } catch (const std::exception &e) {
        std::string error = e.what();
        ALOGE("Exception: %s", error.c_str());
    }

    CONF_modules_free();
    EVP_cleanup();
    ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();

    return 0;
}

