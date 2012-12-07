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
/*
 * @file        ocsp_server_api.h
 * @author
 * @version     1.0
 * @brief       This file contains definitions OCSP server interface & methods.
 */
#ifndef WRT_SRC_RPC_SECURITY_DAEMON_OCSP_SERVER_API_H_
#define WRT_SRC_RPC_SECURITY_DAEMON_OCSP_SERVER_API_H_

#include "ocsp_server_api.h"
#include<string>

namespace WrtSecurity{
namespace OcspServerApi{

// DBus interface name
inline const std::string INTERFACE_NAME()
{
    return "org.tizen.OcspCheck";
}

// Function checks WidgetStatus for installed widget.
// https://106.116.37.24/wiki/WebRuntime/Security/Widget_Signatures
// IN WidgetHandle Widget ID in Database
// OUT WidgetStatus GOOD/REVOKED
inline const std::string CHECK_ACCESS_METHOD()
{
    return "OcspCheck";
}

}
};

#endif // WRT_SRC_RPC_SECURITY_DAEMON_OCSP_SERVER_API_H_
