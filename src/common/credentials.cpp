/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       credentials.cpp
 * @author     Rafal Krypa <r.krypa@samsung.com>
 * @version    1.0
 */

#include <unistd.h>
#include <sys/socket.h>

#include "smack-labels.h"
#include "credentials.h"

namespace SecurityManager {

Credentials Credentials::getCredentialsFromSelf(void)
{
    return Credentials(getpid(), geteuid(), getegid(),
        SmackLabels::getSmackLabelFromSelf());
}

Credentials Credentials::getCredentialsFromSocket(int sock)
{
    struct ucred cr;
    socklen_t len = sizeof(cr);

    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cr, &len) == -1)
        ThrowMsg(Exception::SocketError, "Failed to read peer credentials for sockfd " << sock);

    return Credentials(cr.pid, cr.uid, cr.gid, SmackLabels::getSmackLabelFromSocket(sock));
}

} // namespace SecurityManager
