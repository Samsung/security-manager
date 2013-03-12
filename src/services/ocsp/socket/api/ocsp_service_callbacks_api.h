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
 * @file        ocsp_service_callbacks_api.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Header with api of implemented Ocsp Service callbacks
 */

#ifndef OCSP_SERVICE_CALLBACKS_API_H_
#define OCSP_SERVICE_CALLBACKS_API_H_

#include <string>
#include <utility>
#include "SocketConnection.h"
#include "ocsp_server_api.h"
#include "ocsp_service_callbacks.h"
#include "callback_api.h"

namespace WrtSecurity{
namespace OcspServiceCallbacksApi{

inline const std::pair<std::string, socketServerCallback> CHECK_ACCESS_METHOD_CALLBACK(){
    return std::make_pair(WrtSecurity::OcspServerApi::CHECK_ACCESS_METHOD(),
                          RPC::OcspServiceCallbacks::checkAccess);
}

} // namespace OcspServiceCallbacksApi
} // namespace WrtSecurity

#endif // OCSP_SERVICE_CALLBACKS_API_H_
