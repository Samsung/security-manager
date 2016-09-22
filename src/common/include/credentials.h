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
 * @file       credentials.h
 * @author     Rafal Krypa <r.krypa@samsung.com>
 * @version    1.0
 */

#pragma once

#include <string>
#include <sys/types.h>

#include <dpl/exception.h>

namespace SecurityManager {

class Credentials {
public:
    pid_t pid;    /* process ID of the sending process */
    uid_t uid;    /* user ID of the sending process */
    gid_t gid;    /* group ID of the sending process */
    std::string label; /* security context of the sending process */
    bool authenticated = false;   /* Indicate that the caller has already been authenticated for access */

    Credentials() = delete;
    static Credentials getCredentialsFromSelf(void);
    static Credentials getCredentialsFromSocket(int socket);

    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, SocketError)
    };

private:
    Credentials(pid_t pid, uid_t uid, gid_t gid, std::string &&label) :
        pid(pid), uid(uid), gid(gid), label(std::move(label)) {}
};

} // namespace SecurityManager
