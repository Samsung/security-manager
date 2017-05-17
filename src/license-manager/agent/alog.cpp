/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 */
/**
 * @file    alog.cpp
 * @author  Adam Malinowski <a.malinowsk2@partner.samsung.com>
 * @brief   Simple file containing definition of agent logging level variable.
 */

#include <stdlib.h>

#include "alog.h"

#ifdef BUILD_TYPE_DEBUG
int __alog_level = LOG_DEBUG;
#else
int __alog_level = LOG_ERR;
#endif

static int strlog2intlog(const char *strlog) {
    if (!strncmp("LOG_EMERG", strlog, strlen("LOG_EMERG")))
        return LOG_EMERG;
    if (!strncmp("LOG_ALERT", strlog, strlen("LOG_ALERT")))
        return LOG_ALERT;
    if (!strncmp("LOG_CRIT", strlog, strlen("LOG_CRIT")))
        return LOG_CRIT;
    if (!strncmp("LOG_ERR", strlog, strlen("LOG_ERR")))
        return LOG_ERR;
    if (!strncmp("LOG_WARNING", strlog, strlen("LOG_WARNING")))
        return LOG_WARNING;
    if (!strncmp("LOG_NOTICE", strlog, strlen("LOG_NOTICE")))
        return LOG_NOTICE;
    if (!strncmp("LOG_INFO", strlog, strlen("LOG_INFO")))
        return LOG_INFO;
    if (!strncmp("LOG_DEBUG", strlog, strlen("LOG_DEBUG")))
        return LOG_DEBUG;

    return LOG_ERR;
}

void init_agent_log(void) {
    char *env_val = getenv("LM_LOG_LEVEL");
    if (env_val) {
        __alog_level = strlog2intlog(env_val);
    }
}
