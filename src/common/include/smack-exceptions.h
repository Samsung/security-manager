/*
 *  Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
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
/**
 * @file        smack-exceptions.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Declaration of Smack-specific exceptions
 *
 */
#ifndef _SMACK_EXCEPTIONS_H_
#define _SMACK_EXCEPTIONS_H_

#include <dpl/exception.h>

namespace SecurityManager {

class SmackException {
public:
    DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, LibsmackError)
    DECLARE_EXCEPTION_TYPE(Base, FileError)
    DECLARE_EXCEPTION_TYPE(Base, InvalidLabel)
    DECLARE_EXCEPTION_TYPE(Base, InvalidPathType)
};

} // namespace SecurityManager

#endif /* _SMACK_EXCEPTIONS_H_ */
