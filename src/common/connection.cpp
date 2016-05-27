/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        connection.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@samsung.com)
 * @version     1.0
 * @brief       This file is implementation of common connection functions.
 */

#include "connection.h"
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/smack.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <unistd.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <dpl/errno_string.h>

#include <message-buffer.h>

#include <protocols.h>

namespace {

const int POLL_TIMEOUT = -1;

int waitForSocket(int sock, int event, int timeout) {
    int retval;
    pollfd desc[1];
    desc[0].fd = sock;
    desc[0].events = event;

    while((-1 == (retval = poll(desc, 1, timeout))) && (errno == EINTR)) {
        timeout >>= 1;
        errno = 0;
    }

    if (0 == retval) {
        LogDebug("Poll timeout");
    } else if (-1 == retval) {
        int err = errno;
        LogError("Error in poll: " << GetErrnoString(err));
    }
    return retval;
}

class SockRAII {
public:
    SockRAII()
      : m_sock(-1)
    {}

    virtual ~SockRAII() {
        if (m_sock > -1)
            close(m_sock);
    }

    int Connect(char const * const interface) {
        sockaddr_un clientAddr;
        int flags;

        if (m_sock != -1) // guard
            close(m_sock);

        m_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (m_sock < 0) {
            int err = errno;
            LogError("Error creating socket: " << GetErrnoString(err));
            return SECURITY_MANAGER_ERROR_SOCKET;
        }

        if ((flags = fcntl(m_sock, F_GETFL, 0)) < 0 ||
            fcntl(m_sock, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            int err = errno;
            LogError("Error in fcntl: " << GetErrnoString(err));
            return SECURITY_MANAGER_ERROR_SOCKET;
        }

        memset(&clientAddr, 0, sizeof(clientAddr));

        clientAddr.sun_family = AF_UNIX;

        if (strlen(interface) >= sizeof(clientAddr.sun_path)) {
            LogError("Error: interface name " << interface << "is too long. Max len is:" << sizeof(clientAddr.sun_path));
            return SECURITY_MANAGER_ERROR_NO_SUCH_SERVICE;
        }

        strcpy(clientAddr.sun_path, interface);

        LogDebug("ClientAddr.sun_path = " << interface);

        int retval = TEMP_FAILURE_RETRY(connect(m_sock, (struct sockaddr*)&clientAddr, SUN_LEN(&clientAddr)));
        if ((retval == -1) && (errno == EINPROGRESS)) {
            if (0 >= waitForSocket(m_sock, POLLIN, POLL_TIMEOUT)) {
                LogError("Error in waitForSocket.");
                return SECURITY_MANAGER_ERROR_SOCKET;
            }
            int error = 0;
            socklen_t len = sizeof(error);
            retval = getsockopt(m_sock, SOL_SOCKET, SO_ERROR, &error, &len);

            if (-1 == retval) {
                int err = errno;
                LogError("Error in getsockopt: " << GetErrnoString(err));
                return SECURITY_MANAGER_ERROR_SOCKET;
            }

            if (error == EACCES) {
                LogError("Access denied");
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
            }

            if (error != 0) {
                LogError("Error in connect: " << GetErrnoString(error));
                return SECURITY_MANAGER_ERROR_SOCKET;
            }

            return SECURITY_MANAGER_SUCCESS;
        }

        if (-1 == retval) {
            int err = errno;
            LogError("Error connecting socket: " << GetErrnoString(err));
            if (err == EACCES)
                return SECURITY_MANAGER_ERROR_ACCESS_DENIED;
            if (err == ENOTSOCK)
                return SECURITY_MANAGER_ERROR_NO_SUCH_SERVICE;
            return SECURITY_MANAGER_ERROR_SOCKET;
        }

        return SECURITY_MANAGER_SUCCESS;
    }

    int Get() {
        return m_sock;
    }

private:
    int m_sock;
};

} // namespace anonymous

namespace SecurityManager {

int sendToServer(char const * const interface, const RawBuffer &send, MessageBuffer &recv) {
    int ret;
    SockRAII sock;
    ssize_t done = 0;
    char buffer[2048];

    if (SECURITY_MANAGER_SUCCESS != (ret = sock.Connect(interface))) {
        LogError("Error in SockRAII");
        return ret;
    }

    while ((send.size() - done) > 0) {
        if (0 >= waitForSocket(sock.Get(), POLLOUT, POLL_TIMEOUT)) {
            LogError("Error in poll(POLLOUT)");
            return SECURITY_MANAGER_ERROR_SOCKET;
        }
        ssize_t temp = TEMP_FAILURE_RETRY(write(sock.Get(), &send[done], send.size() - done));
        if (-1 == temp) {
            int err = errno;
            LogError("Error in write: " << GetErrnoString(err));
            return SECURITY_MANAGER_ERROR_SOCKET;
        }
        done += temp;
    }

    do {
        if (0 >= waitForSocket(sock.Get(), POLLIN, POLL_TIMEOUT)) {
            LogError("Error in poll(POLLIN)");
            return SECURITY_MANAGER_ERROR_SOCKET;
        }
        ssize_t temp = TEMP_FAILURE_RETRY(read(sock.Get(), buffer, 2048));
        if (-1 == temp) {
            int err = errno;
            LogError("Error in read: " << GetErrnoString(err));
            return SECURITY_MANAGER_ERROR_SOCKET;
        }

        if (0 == temp) {
            LogError("Read return 0/Connection closed by server(?)");
            return SECURITY_MANAGER_ERROR_SOCKET;
        }

        RawBuffer raw(buffer, buffer+temp);
        recv.Push(raw);
    } while(!recv.Ready());
    return SECURITY_MANAGER_SUCCESS;
}

int sendToServerAncData(char const * const interface, const RawBuffer &send, struct msghdr &hdr) {
    int ret;
    SockRAII sock;
    ssize_t done = 0;

    if (SECURITY_MANAGER_SUCCESS != (ret = sock.Connect(interface))) {
        LogError("Error in SockRAII");
        return ret;
    }

    while ((send.size() - done) > 0) {
        if (0 >= waitForSocket(sock.Get(), POLLOUT, POLL_TIMEOUT)) {
            LogError("Error in poll(POLLOUT)");
            return SECURITY_MANAGER_ERROR_SOCKET;
        }
        ssize_t temp = TEMP_FAILURE_RETRY(write(sock.Get(), &send[done], send.size() - done));
        if (-1 == temp) {
            int err = errno;
            LogError("Error in write: " << GetErrnoString(err));
            return SECURITY_MANAGER_ERROR_SOCKET;
        }
        done += temp;
    }

    if (0 >= waitForSocket(sock.Get(), POLLIN, POLL_TIMEOUT)) {
        LogError("Error in poll(POLLIN)");
        return SECURITY_MANAGER_ERROR_SOCKET;
    }

    ssize_t temp = TEMP_FAILURE_RETRY(recvmsg(sock.Get(), &hdr, MSG_CMSG_CLOEXEC));

    if (temp < 0) {
        int err = errno;
        LogError("Error in recvmsg(): " << GetErrnoString(err) << " errno: " << err);
        return SECURITY_MANAGER_ERROR_SOCKET;
    }

    if (0 == temp) {
        LogError("Read return 0/Connection closed by server(?)");
        return SECURITY_MANAGER_ERROR_SOCKET;
    }

    return SECURITY_MANAGER_SUCCESS;
}

} // namespace SecurityManager
