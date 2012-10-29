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
 * @file        security_daemon_dbus_config.h
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains security daemon DBus configuration.
 */
#ifndef WRT_SRC_RPC_SECURITY_DAEMON_DBUS_CONFIG_H_
#define WRT_SRC_RPC_SECURITY_DAEMON_DBUS_CONFIG_H_

#include <string>

namespace WrtSecurity {

struct SecurityDaemonConfig {
    static const std::string OBJECT_PATH()
    {
        return "/org/tizen/SecurityDaemon";
    }

    static const std::string SERVICE_NAME()
    {
        return "org.tizen.SecurityDaemon";
    }
};

} // namespace WrtSecurity

#endif // WRT_SRC_RPC_SECURITY_DAEMON_DBUS_CONFIG_H_
