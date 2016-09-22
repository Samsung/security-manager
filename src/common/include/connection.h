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
 * @file        connection.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@samsung.com)
 * @version     1.0
 * @brief       This file constains declarations of connection-related functions
 *              used in security manager.
 */

#pragma once

#include <vector>
#include <functional>

#include <message-buffer.h>

extern "C" {
    struct msghdr;
}

namespace SecurityManager {

typedef std::vector<unsigned char> RawBuffer;

int sendToServer(char const * const interface, const RawBuffer &send, MessageBuffer &recv);

/*
 * sendToServerAncData is special case when we want to receive file descriptor
 * passed by Security Manager on behalf of calling process. We can't get it with
 * MessageBuffer.
 *
 * This function should be called _ONLY_ in this particular case.
 *
 */
int sendToManagerAncData(char const * const interface, const RawBuffer &send, struct msghdr &hdr);

} // namespace SecurityManager
