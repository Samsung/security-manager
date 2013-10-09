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
 * @file        generic-socket-manager.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementation of GenericSocketService and GenericSocketManager.
 */

#include <sys/socket.h>
#include <sys/types.h>

#include <generic-socket-manager.h>

namespace SecurityServer {

class SendMsgData::Internal {
public:
    Internal(int resultCode, int fileDesc)
      : m_resultCode(resultCode)
      , m_fileDesc(fileDesc)
    {
        memset(&m_hdr, 0, sizeof(msghdr));
        memset(m_cmsgbuf, 0, CMSG_SPACE(sizeof(int)));

        m_iov.iov_base = &m_resultCode;
        m_iov.iov_len = sizeof(m_resultCode);

        m_hdr.msg_iov = &m_iov;
        m_hdr.msg_iovlen = 1;

        if (fileDesc != -1) {
            m_hdr.msg_control = m_cmsgbuf;
            m_hdr.msg_controllen = CMSG_SPACE(sizeof(int));

            m_cmsg = CMSG_FIRSTHDR(&m_hdr);
            m_cmsg->cmsg_len = CMSG_LEN(sizeof(int));
            m_cmsg->cmsg_level = SOL_SOCKET;
            m_cmsg->cmsg_type = SCM_RIGHTS;

            memmove(CMSG_DATA(m_cmsg), &m_fileDesc, sizeof(int));
        }
    }

    msghdr* data() { return &m_hdr; }

private:
    msghdr m_hdr;
    iovec m_iov;
    cmsghdr *m_cmsg;
    unsigned char m_cmsgbuf[CMSG_SPACE(sizeof(int))];
    int m_resultCode;
    int m_fileDesc;
};

SendMsgData::SendMsgData()
  : m_resultCode(0)
  , m_fileDesc(-1)
  , m_flags(0)
  , m_pimpl(NULL)
{}

SendMsgData::SendMsgData(int resultCode, int fileDesc, int flags)
  : m_resultCode(resultCode)
  , m_fileDesc(fileDesc)
  , m_flags(flags)
  , m_pimpl(NULL)
{}

SendMsgData::SendMsgData(const SendMsgData &second)
  : m_resultCode(second.m_resultCode)
  , m_fileDesc(second.m_fileDesc)
  , m_flags(second.m_flags)
  , m_pimpl(NULL)
{}

SendMsgData::~SendMsgData() {
    delete m_pimpl;
}

SendMsgData& SendMsgData::operator=(const SendMsgData &second) {
    m_resultCode = second.m_resultCode;
    m_fileDesc = second.m_fileDesc;
    m_flags = second.m_flags;
    delete m_pimpl;
    m_pimpl = NULL;
    return *this;
}

msghdr* SendMsgData::getMsghdr() {
    if (!m_pimpl)
        m_pimpl = new Internal(m_resultCode, m_fileDesc);
    return m_pimpl->data();
}

int SendMsgData::flags() {
    return m_flags;
}

} // namespace SecurityServer

