/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bartlomiej Grzelewski <b.grzelewski@samsung.com>
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
 * @file        installer.h
 * @author      Michal Witanowski (m.witanowski@samsung.com)
 * @brief       Implementation of installer service for libprivilege-control encapsulation.
 */

#ifndef _SECURITY_SERVER_INSTALLER_
#define _SECURITY_SERVER_INSTALLER_

#include <service-thread.h>
#include <generic-socket-manager.h>
#include <message-buffer.h>
#include <connection-info.h>

namespace SecurityServer {

class InstallerException
{
public:
    DECLARE_EXCEPTION_TYPE(SecurityServer::Exception, Base)
    DECLARE_EXCEPTION_TYPE(Base, InvalidAction)
};

class InstallerService :
    public SecurityServer::GenericSocketService,
    public SecurityServer::ServiceThread<InstallerService>
{
public:
    InstallerService();
    ServiceDescriptionVector GetServiceDescription();

    DECLARE_THREAD_EVENT(AcceptEvent, accept)
    DECLARE_THREAD_EVENT(WriteEvent, write)
    DECLARE_THREAD_EVENT(ReadEvent, process)
    DECLARE_THREAD_EVENT(CloseEvent, close)

    void accept(const AcceptEvent &event);
    void write(const WriteEvent &event);
    void process(const ReadEvent &event);
    void close(const CloseEvent &event);

    static const char *const LABEL_FOR_PUBLIC_APP_PATH;

private:
    ConnectionInfoMap m_connectionInfoMap;

    /**
     * Handle request from a client
     *
     * @param  conn        Socket connection information
     * @param  buffer      Raw received data buffer
     * @param  interfaceID identifier used to distinguish source socket
     * @return             true on success
     */
    bool processOne(const ConnectionID &conn, MessageBuffer &buffer, InterfaceID interfaceID);

    /**
     * Process application installation
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @return        true on success
     */
    bool processAppInstall(MessageBuffer &buffer, MessageBuffer &send);

    /**
     * Process libprivilege-control action and store result in a bufer
     *
     * @param  buffer Raw received data buffer
     * @param  send   Raw data buffer to be sent
     * @return        true on success
     */
    bool processAppUninstall(MessageBuffer &buffer, MessageBuffer &send);
};

} // namespace SecurityServer

#endif // _SECURITY_SERVER_INSTALLER_
