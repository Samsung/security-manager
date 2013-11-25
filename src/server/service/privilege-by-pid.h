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
/*hcpp
 * @author      Jan Cybulski (j.cybulski@samsung.com)
 * @version     1.0
 * @brief       Implementation of api-check-privilege-by-pid
 */

#ifndef _SECURITY_SERVER_PRIVILEGE_BY_PID_
#define _SECURITY_SERVER_PRIVILEGE_BY_PID_

#include <service-thread.h>
#include <generic-socket-manager.h>

#include <message-buffer.h>

namespace SecurityServer {

class PrivilegeByPidService
  : public SecurityServer::GenericSocketService
  , public SecurityServer::ServiceThread<PrivilegeByPidService>
{
public:
    typedef std::map<int, MessageBuffer> MessageBufferMap;

    ServiceDescriptionVector GetServiceDescription();

    DECLARE_THREAD_EVENT(AcceptEvent, accept)
    DECLARE_THREAD_EVENT(WriteEvent, write)
    DECLARE_THREAD_EVENT(ReadEvent, process)
    DECLARE_THREAD_EVENT(CloseEvent, close)

    void accept(const AcceptEvent &event);
    void write(const WriteEvent &event);
    void process(const ReadEvent &event);
    void close(const CloseEvent &event);
private:
    bool processOne(const ConnectionID &conn, MessageBuffer &buffer);

    MessageBufferMap m_messageBufferMap;
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_DATA_SHARE_