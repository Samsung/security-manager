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
/**
 * @file        security_daemon_socket_config.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief
 */

#ifndef SECURITY_DAEMON_SOCKET_CONFIG_H_
#define SECURITY_DAEMON_SOCKET_CONFIG_H_

#include <string>
#include <signal.h>

namespace WrtSecurity {

struct SecurityDaemonSocketConfig {
    static const std::string SERVER_ADDRESS()
    {
        return "/tmp/server";
    }
};

} // namespace WrtSecurity
#endif /* SECURITY_DAEMON_SOCKET_CONFIG_H_ */
