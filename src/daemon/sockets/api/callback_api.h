/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
/*
 * @file        callback_api.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This header provides types and exceptions required for security service callbacks
 */

#ifndef CALLBACK_API_H_
#define CALLBACK_API_H_

#include <dpl/exception.h>

typedef void (*socketServerCallback) (SocketConnection * connector);

typedef bool (*securityCheck) (int socketfd);

namespace ServiceCallbackApi{

    class Exception{
    public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, ServiceCallbackException)
    };

}

#endif /* CALLBACK_API_H_ */
