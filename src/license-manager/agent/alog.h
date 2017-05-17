/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Adam Malinowski <a.malinowsk2@partner.samsung.com>
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
 * @file        alog.h
 * @author      Adam Malinowski <a.malinowsk2@partner.samsung.com>
 * @version     1.0
 * @brief       This file defines agent logging utilities.
 */

#pragma once

#include <sstream>
#include <systemd/sd-journal.h>

#include <attributes/attributes.h>

extern int __alog_level;

namespace {
// One of these templates might not get instantiated, so they have to be marked as (possibly) unused
    template <typename ...Args>
    void UNUSED __ALOG_FUN(int level, const std::stringstream &format,
                                            Args&&... args) {
        sd_journal_print(level, format.str().c_str(), std::forward<Args>(args)...);
    }
    template <>
    void UNUSED __ALOG_FUN(int level, const std::stringstream &format) {
        sd_journal_print(level, "%s", format.str().c_str());
    }
}

#define __ALOG(LEVEL, FORMAT, ...) \
    do { \
        if (LEVEL <= __alog_level) { \
            std::stringstream __LOG_MACRO_format; \
            __LOG_MACRO_format << FORMAT; \
            __ALOG_FUN(LEVEL, __LOG_MACRO_format, ##__VA_ARGS__); \
        } \
    } while (0)

#define ALOGE_ERRNO(MESSAGE) \
    do { \
        if (LOG_ERR <= __alog_level) { \
            constexpr int bufsize = 1024; \
            char buf[bufsize]; \
            char *err_str = strerror_r(errno, buf, bufsize); \
            std::stringstream __LOG_msg; \
            __LOG_msg << MESSAGE << " : " << err_str; \
            __ALOG_FUN(LOG_ERR, __LOG_msg); \
        } \
    } while(0)

#define ALOGM(...)  __ALOG(LOG_EMERG, __VA_ARGS__)   /* system is unusable */
#define ALOGA(...)  __ALOG(LOG_ALERT, __VA_ARGS__)   /* action must be taken immediately */
#define ALOGC(...)  __ALOG(LOG_CRIT, __VA_ARGS__)    /* critical conditions */
#define ALOGE(...)  __ALOG(LOG_ERR, __VA_ARGS__)     /* error conditions */
#define ALOGW(...)  __ALOG(LOG_WARNING, __VA_ARGS__) /* warning conditions */
#define ALOGN(...)  __ALOG(LOG_NOTICE, __VA_ARGS__)  /* normal but significant condition */
#define ALOGI(...)  __ALOG(LOG_INFO, __VA_ARGS__)    /* informational */
#define ALOGD(...)  __ALOG(LOG_DEBUG, __VA_ARGS__)   /* debug-level messages */

void init_agent_log(void);
