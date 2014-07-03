/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        cynara.cpp
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Wrapper class for Cynara interface
 */

#include <string>
#include "cynara.h"

namespace SecurityManager {

static void checkCynaraAdminError(int result, const std::string &msg)
{
    switch (result) {
        case CYNARA_ADMIN_API_SUCCESS:
            return;
        case CYNARA_ADMIN_API_OUT_OF_MEMORY:
            ThrowMsg(CynaraException::OutOfMemory, msg);
        case CYNARA_ADMIN_API_INVALID_PARAM:
            ThrowMsg(CynaraException::InvalidParam, msg);
        case CYNARA_ADMIN_API_SERVICE_NOT_AVAILABLE:
            ThrowMsg(CynaraException::ServiceNotAvailable, msg);
        default:
            ThrowMsg(CynaraException::UnknownError, msg);
    }
}

CynaraAdmin::CynaraAdmin()
{
    checkCynaraAdminError(
        cynara_admin_initialize(&m_CynaraAdmin),
        "Cannot connect to Cynara administrative interface.");
}

CynaraAdmin::~CynaraAdmin()
{
    cynara_admin_finish(m_CynaraAdmin);
}

} // namespace SecurityManager
