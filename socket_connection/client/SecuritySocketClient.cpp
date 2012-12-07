/*
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        SecuritySocketClient.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implemtation of socket client class.
 */

#include <sys/socket.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/un.h>
#include <errno.h>

#include "SecuritySocketClient.h"
#include "security_daemon_socket_config.h"

void SecuritySocketClient::throwWithErrnoMessage(const std::string& specificInfo){
    LogError(specificInfo << " : " << strerror(errno));
    ThrowMsg(Exception::SecuritySocketClientException, specificInfo << " : " << strerror(errno));
}

SecuritySocketClient::SecuritySocketClient(const std::string& interfaceName) {
    m_interfaceName = interfaceName;
    m_serverAddress = WrtSecurity::SecurityDaemonSocketConfig::SERVER_ADDRESS();
    LogInfo("Client created");
}

void SecuritySocketClient::connect(){
    struct sockaddr_un remote;
    if(-1 == (m_socketFd = socket(AF_UNIX, SOCK_STREAM,0))){
        throwWithErrnoMessage("socket()");
    }

    //socket needs to be nonblocking, because read can block after select
    int flags;
    if (-1 == (flags = fcntl(m_socketFd, F_GETFL, 0)))
        flags = 0;
    if(-1 == (fcntl(m_socketFd, F_SETFL, flags | O_NONBLOCK))){
        throwWithErrnoMessage("fcntl");
    }

    bzero(&remote, sizeof(remote));
    remote.sun_family = AF_UNIX;
    strcpy(remote.sun_path, m_serverAddress.c_str());
    if(-1 == ::connect(m_socketFd, (struct sockaddr *)&remote, SUN_LEN(&remote))){
        throwWithErrnoMessage("connect()");
    }

    m_socketConnector.reset(new SocketConnection(m_socketFd));

    LogInfo("Client connected");
}

void SecuritySocketClient::disconnect(){
    //Socket should be already closed by server side, 
    //even though we should close it in case of any errors
    close(m_socketFd);
    LogInfo("Client disconnected");
}
