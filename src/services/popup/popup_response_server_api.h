/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file    popup_response_server_api.h
 * @author  Zbigniew Kostrzewa (z.kostrzewa@samsung.com)
 * @version 1.0
 * @brief
 */

#ifndef WRT_SRC_RPC_SECURITY_DAEMON_API_POPUP_RESPONSE_SERVER_API_H
#define WRT_SRC_RPC_SECURITY_DAEMON_API_POPUP_RESPONSE_SERVER_API_H

#include <string>

namespace WrtSecurity{
namespace PopupServerApi{

inline const std::string INTERFACE_NAME()
{
    return "org.tizen.PopupResponse";
}

inline const std::string VALIDATION_METHOD()
{
    return "validate";
}

}
}

#endif // WRT_SRC_RPC_SECURITY_DAEMON_API_POPUP_RESPONSE_SERVER_API_H

