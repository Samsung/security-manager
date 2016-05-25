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
 * @file        tzplatform-config.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Interface for tizenplatform-config module - header file
 */

#pragma once

#include <string>
#include <tzplatform_config.h>

#include "dpl/exception.h"

namespace SecurityManager {

class TizenPlatformConfig {
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base);
        DECLARE_EXCEPTION_TYPE(Base, ContextError);
        DECLARE_EXCEPTION_TYPE(Base, ValueError);
    };

    TizenPlatformConfig(uid_t uid);
    ~TizenPlatformConfig();

    std::string ctxGetEnv(enum tzplatform_variable id);

    std::string ctxMakePath(enum tzplatform_variable id, const std::string &p);

    std::string ctxMakePath(enum tzplatform_variable id, const std::string &p1, const std::string &p2);

    std::string ctxMakePath(enum tzplatform_variable id, const std::string &p1, const std::string &p2, const std::string &p3);


    static std::string getEnv(enum tzplatform_variable id);

    static std::string makePath(enum tzplatform_variable id, const std::string &p);

    static std::string makePath(enum tzplatform_variable id, const std::string &p1, const std::string &p2);

    static std::string makePath(enum tzplatform_variable id, const std::string &p1, const std::string &p2, const std::string &p3);

    static uid_t getUid(enum tzplatform_variable id);

private:
    struct tzplatform_context *m_ctx;
};

}
