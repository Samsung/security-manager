/*
 *  Copyright (c) 2014-2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
/*
 * @file        tzplatform-config.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Interface for tizenplatform-config module
 */

#include "tzplatform-config.h"

namespace SecurityManager {

TizenPlatformConfig::TizenPlatformConfig(uid_t uid)
{
    if (tzplatform_context_create(&m_ctx) || m_ctx == nullptr)
        ThrowMsg(Exception::ContextError, "Error in tzplatform_context_create()");

    if (tzplatform_context_set_user(m_ctx, uid)) {
        tzplatform_context_destroy(m_ctx);
        ThrowMsg(Exception::ContextError, "Error in tzplatform_context_set_user()");
    }
}

TizenPlatformConfig::~TizenPlatformConfig()
{
    tzplatform_context_destroy(m_ctx);
}

static std::string validate(const char *str)
{
    if (str == nullptr)
        ThrowMsg(TizenPlatformConfig::Exception::ValueError,
            "Invalid value returned by tzplatform-config");
    return str;
}

static uid_t validate(uid_t uid)
{
    if (uid == static_cast<uid_t>(-1))
        ThrowMsg(TizenPlatformConfig::Exception::ValueError,
            "Invalid value returned by tzplatform-config");
    return uid;
}

std::string TizenPlatformConfig::ctxGetEnv(enum tzplatform_variable id)
{
    return validate(tzplatform_context_getenv(m_ctx, id));
}

std::string TizenPlatformConfig::ctxMakePath(enum tzplatform_variable id,
    const std::string &p)
{
    return validate(tzplatform_context_mkpath(m_ctx, id, p.c_str()));
}

std::string TizenPlatformConfig::ctxMakePath(enum tzplatform_variable id,
    const std::string &p1, const std::string &p2)
{
    return validate(tzplatform_context_mkpath3(m_ctx, id, p1.c_str(), p2.c_str()));
}

std::string TizenPlatformConfig::ctxMakePath(enum tzplatform_variable id,
    const std::string &p1, const std::string &p2, const std::string &p3)
{
    return validate(tzplatform_context_mkpath4(m_ctx, id, p1.c_str(), p2.c_str(), p3.c_str()));
}

std::string TizenPlatformConfig::getEnv(enum tzplatform_variable id)
{
    return validate(tzplatform_getenv(id));
}

std::string TizenPlatformConfig::makePath(enum tzplatform_variable id,
    const std::string &p)
{
    return validate(tzplatform_mkpath(id, p.c_str()));
}

std::string TizenPlatformConfig::makePath(enum tzplatform_variable id,
    const std::string &p1, const std::string &p2)
{
    return validate(tzplatform_mkpath3(id, p1.c_str(), p2.c_str()));
}

std::string TizenPlatformConfig::makePath(enum tzplatform_variable id,
    const std::string &p1, const std::string &p2, const std::string &p3)
{
    return validate(tzplatform_mkpath4(id, p1.c_str(), p2.c_str(), p3.c_str()));
}

uid_t TizenPlatformConfig::getUid(enum tzplatform_variable id)
{
    return validate(tzplatform_getuid(id));
}

}
