/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        password-exception.h
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Definition of PasswordException class.
 */

#ifndef _PASSWORD_EXCEPTION_H_
#define _PASSWORD_EXCEPTION_H_

#include <dpl/exception.h>

namespace SecurityServer
{
    class PasswordException
    {
    public:
        DECLARE_EXCEPTION_TYPE(SecurityServer::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, OutOfData)
        DECLARE_EXCEPTION_TYPE(Base, NoData)
        DECLARE_EXCEPTION_TYPE(Base, FStreamOpenError)
        DECLARE_EXCEPTION_TYPE(Base, FStreamWriteError)
        DECLARE_EXCEPTION_TYPE(Base, FStreamReadError)
        DECLARE_EXCEPTION_TYPE(Base, MemoryError)
        DECLARE_EXCEPTION_TYPE(Base, NoPasswords)
        DECLARE_EXCEPTION_TYPE(Base, PasswordNotActive)
        DECLARE_EXCEPTION_TYPE(Base, MakeDirError)
        DECLARE_EXCEPTION_TYPE(Base, TimerError)
    };
} //namespace SecurityServer

#endif //_PASSWORD_EXCEPTION_H_
