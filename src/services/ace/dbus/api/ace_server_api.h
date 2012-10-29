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
 * @file        ace_server_api.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains definitions ACE server interface & methods.
 */
#ifndef WRT_SRC_RPC_SECURITY_DAEMON_ACE_SERVER_API_H_
#define WRT_SRC_RPC_SECURITY_DAEMON_ACE_SERVER_API_H_

#include<string>


namespace WrtSecurity{
namespace AceServerApi{

    // DBus interface names
    inline const std::string INTERFACE_NAME()
    {
        return "org.tizen.AceCheckAccessInterface";
    }

    // RPC test function
    // IN std::string
    // OUT std::string
    inline const std::string ECHO_METHOD()
    {
        return "echo";
    }

    // IN string subject
    // IN string resource
    // IN vector<string> function param names
    // IN vector<string> function param values
    // OUT int allow, deny, popup type
    inline const std::string CHECK_ACCESS_METHOD()
    {
        return "check_access";
    }

    // IN string subject
    // IN string resource
    // OUT int allow, deny, popup type
    inline const std::string CHECK_ACCESS_INSTALL_METHOD()
    {
        return "check_access_install";
    }

    // Policy update trigger
    inline const std::string UPDATE_POLICY_METHOD()
    {
        return "update_policy";
    }
};
};


#endif // WRT_SRC_RPC_SECURITY_DAEMON_ACE_SERVER_API_H_
