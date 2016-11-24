/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        connection-info.h
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Definition of ConnectionInfo structure and ConnectionInfoMap type.
 */

#pragma once

#include <map>
#include <generic-socket-manager.h>
#include <message-buffer.h>

namespace SecurityManager
{
    struct ConnectionInfo {
        InterfaceID interfaceID;
        MessageBuffer buffer;
    };

    typedef std::map<int, ConnectionInfo> ConnectionInfoMap;
} //namespace SecurityManager
