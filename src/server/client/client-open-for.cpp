/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        client-open-for-cookie.cpp
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation of security-server API
 *              for file opening.
 */

#include <cstring>

#include <dpl/log/log.h>
#include <dpl/exception.h>

#include <message-buffer.h>
#include <client-common.h>
#include <protocols.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <security-server.h>

SECURITY_SERVER_API
int security_server_open_for(const char *filename, int *fd)
{
   using namespace SecurityServer;
    try {
        if (NULL == filename || std::string(filename).empty()) {
            LogError("Error input param.");
            return SECURITY_SERVER_API_ERROR_INPUT_PARAM;
        }

        MessageBuffer send;

        Serialization::Serialize(send, std::string(filename));

        struct msghdr hdr;
        struct iovec iov;
        struct cmsghdr *cmsg = NULL;
        int retcode = -1;
        int result = -1;
        unsigned char cmsgbuf[CMSG_SPACE(sizeof(int))];

        memset(&hdr, 0, sizeof(struct msghdr));
        memset(cmsgbuf, 0, CMSG_SPACE(sizeof(int)));

        iov.iov_base = &retcode;
        iov.iov_len = sizeof(retcode);
        hdr.msg_iov = &iov;
        hdr.msg_iovlen = 1;

        hdr.msg_control = cmsgbuf;
        hdr.msg_controllen = CMSG_SPACE(sizeof(int));

        result = sendToServerAncData(SERVICE_SOCKET_OPEN_FOR, send.Pop(), hdr);
        if (result != SECURITY_SERVER_API_SUCCESS) {
            *fd = -1;
            return result;
        }

        if (hdr.msg_flags & MSG_CTRUNC) {
            LogError("Not enough space for ancillary element array.");
            *fd = -1;
            return SECURITY_SERVER_API_ERROR_BUFFER_TOO_SMALL;
        }

        for(cmsg = CMSG_FIRSTHDR(&hdr); cmsg != NULL; cmsg = CMSG_NXTHDR(&hdr, cmsg)) {
            if((SOL_SOCKET == cmsg->cmsg_level) && (SCM_RIGHTS == cmsg->cmsg_type)) {
                memmove(fd, CMSG_DATA(cmsg), sizeof(int));
            }
        }

        return retcode;
    } catch (MessageBuffer::Exception::Base &e) {
        LogDebug("SecurityServer::MessageBuffer::Exception " << e.DumpToString());
    } catch (std::exception &e) {
        LogDebug("STD exception " << e.what());
    } catch (...) {
        LogDebug("Unknown exception occured");
    }
    return SECURITY_SERVER_API_ERROR_UNKNOWN;
}
