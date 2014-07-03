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
 * @file        cynara.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @brief       Wrapper class for Cynara interface
 */

#ifndef _SECURITY_MANAGER_CYNARA_
#define _SECURITY_MANAGER_CYNARA_

#include <cynara-admin.h>
#include <dpl/exception.h>

namespace SecurityManager {

class CynaraException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, OutOfMemory)
    DECLARE_EXCEPTION_TYPE(Base, InvalidParam)
    DECLARE_EXCEPTION_TYPE(Base, ServiceNotAvailable)
    DECLARE_EXCEPTION_TYPE(Base, UnknownError)
};

class CynaraAdmin
{
public:
    CynaraAdmin();
    virtual ~CynaraAdmin();

private:
    struct cynara_admin *m_CynaraAdmin;
};

} // namespace SecurityManager

#endif // _SECURITY_MANAGER_CYNARA_
