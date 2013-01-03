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
 * @file        security_socket_service.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of socket server
 */
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/signalfd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <cstring>
#include <dpl/log/log.h>
#include "ace_service_callbacks_api.h"
#include "ocsp_service_callbacks_api.h"
#include "popup_service_callbacks_api.h"
#include "security_daemon_socket_config.h"
#include "security_socket_service.h"

#define TIMEOUT_SEC 0
#define TIMEOUT_NSEC 100000000
#define MAX_LISTEN 5
#define SIGNAL_TO_CLOSE SIGUSR1

void SecuritySocketService::throwWithErrnoMessage(const std::string& specificInfo){
    LogError(specificInfo << " : " << strerror(errno));
    ThrowMsg(DPL::Exception, specificInfo << " : " << strerror(errno));
}

void SecuritySocketService::registerServiceCallback(const std::string &interfaceName,
                                                    const std::string &methodName,
                                                    socketServerCallback callbackMethod,
                                                    securityCheck securityMethod){
    if(NULL == callbackMethod){
        LogError("Null callback");
        ThrowMsg(DPL::Exception, "Null callback");
    }
    if(interfaceName.empty() || methodName.empty()){
        LogError("Interface and method name cannot be empty");
        ThrowMsg(DPL::Exception, "Empty interface or method name");
    }

    auto serviceCallbackPtr = std::make_shared<ServiceCallback>(ServiceCallback(callbackMethod, securityMethod));
    m_callbackMap[interfaceName][methodName] = serviceCallbackPtr;
}

void SecuritySocketService::addClientSocket(int clientSocket){
    std::lock_guard<std::mutex> guard(m_clientSocketListMutex);
    m_clientSocketList.push_back(clientSocket);
}

void SecuritySocketService::removeClientSocket(int clientSocket){
    std::lock_guard<std::mutex> guard(m_clientSocketListMutex);
    m_clientSocketList.remove(clientSocket);
}

bool SecuritySocketService::popClientSocket(int * clientSocket){
    std::lock_guard<std::mutex> guard(m_clientSocketListMutex);
    if(m_clientSocketList.empty())
        return false;
    *clientSocket = m_clientSocketList.front();
    m_clientSocketList.pop_front();
    return true;
}

void SecuritySocketService::initialize(){

    LogInfo("Initializing...");
    m_serverAddress = WrtSecurity::SecurityDaemonSocketConfig::SERVER_ADDRESS();
    m_signalToClose = SIGNAL_TO_CLOSE;

    //registering Ace callbacks
    registerServiceCallback(WrtSecurity::AceServerApi::INTERFACE_NAME(),
                            WrtSecurity::AceServiceCallbacksApi::CHECK_ACCESS_METHOD_CALLBACK().first,
                            WrtSecurity::AceServiceCallbacksApi::CHECK_ACCESS_METHOD_CALLBACK().second);

    registerServiceCallback(WrtSecurity::AceServerApi::INTERFACE_NAME(),
                            WrtSecurity::AceServiceCallbacksApi::CHECK_ACCESS_INSTALL_METHOD_CALLBACK().first,
                            WrtSecurity::AceServiceCallbacksApi::CHECK_ACCESS_INSTALL_METHOD_CALLBACK().second);

    registerServiceCallback(WrtSecurity::AceServerApi::INTERFACE_NAME(),
                            WrtSecurity::AceServiceCallbacksApi::UPDATE_POLICY_METHOD_CALLBACK().first,
                            WrtSecurity::AceServiceCallbacksApi::UPDATE_POLICY_METHOD_CALLBACK().second);
    LogInfo("Registered Ace callbacks");

    //registering Ocsp callbacks
    registerServiceCallback(WrtSecurity::OcspServerApi::INTERFACE_NAME(),
                            WrtSecurity::OcspServiceCallbacksApi::CHECK_ACCESS_METHOD_CALLBACK().first,
                            WrtSecurity::OcspServiceCallbacksApi::CHECK_ACCESS_METHOD_CALLBACK().second);
    LogInfo("Registered Ocsp callbacks");

    //registering Popup callbacks
    registerServiceCallback(WrtSecurity::PopupServerApi::INTERFACE_NAME(),
                            WrtSecurity::PopupServiceCallbacksApi::VALIDATION_METHOD_CALLBACK().first,
                            WrtSecurity::PopupServiceCallbacksApi::VALIDATION_METHOD_CALLBACK().second);
    LogInfo("Registered Popup callbacks");

    if(-1 == (m_listenFd = socket(AF_UNIX, SOCK_STREAM, 0))){
        throwWithErrnoMessage("socket()");
    }
    LogInfo("Server socket created");

    //socket needs to be nonblocking, because read can block after select
    int flags;
    if (-1 == (flags = fcntl(m_listenFd, F_GETFL, 0)))
        flags = 0;
    if(-1 == (fcntl(m_listenFd, F_SETFL, flags | O_NONBLOCK))){
        throwWithErrnoMessage("fcntl");
    }

    sockaddr_un server_address;
    bzero(&server_address, sizeof(server_address));
    server_address.sun_family = AF_UNIX;
    strcpy(server_address.sun_path, m_serverAddress.c_str());
    unlink(server_address.sun_path);

    mode_t socket_umask, original_umask;
    socket_umask = 0;
    original_umask = umask(socket_umask);

    if(-1 == bind(m_listenFd, (struct sockaddr *)&server_address, SUN_LEN(&server_address))){
        throwWithErrnoMessage("bind()");
    }

    umask(original_umask);

    LogInfo("Initialized");
}

void SecuritySocketService::start(){

    LogInfo("Starting...");
    if(m_serverAddress.empty()){
        LogError("Server not initialized");
        ThrowMsg(DPL::Exception, "Server not initialized");
    }

    sigset_t sigset;
    sigemptyset(&sigset);
    if(-1 == sigaddset(&sigset, m_signalToClose)){
        throwWithErrnoMessage("sigaddset()");
    }
    int returned_value;
    if ((returned_value = pthread_sigmask(SIG_BLOCK, &sigset, NULL)) < 0) {
        errno = returned_value;
        throwWithErrnoMessage("pthread_sigmask()");
    }

    pthread_t mainThread;
    if((returned_value = pthread_create(&mainThread, NULL, &serverThread, this)) < 0){
        errno = returned_value;
        throwWithErrnoMessage("pthread_create()");
    }
    m_mainThread = mainThread;

    LogInfo("Started");
}

void * SecuritySocketService::serverThread(void * data){
    pthread_detach(pthread_self());
    SecuritySocketService &t = *static_cast<SecuritySocketService *>(data);
    LogInfo("Running server main thread");
    Try {
        t.mainLoop();
    } Catch (DPL::Exception) {
        LogError("Socket server error. Exiting...");
        return (void *)1;
    }

    return (void *)0;
}


void SecuritySocketService::mainLoop(){

    if(listen(m_listenFd, MAX_LISTEN) == -1){
        throwWithErrnoMessage("listen()");
    }

    //Settings to catch closing signal in select
    int signal_fd;
    sigset_t sigset;
    if(-1 == (sigemptyset(&sigset))){
        throwWithErrnoMessage("sigemptyset()");
    }
    if(-1 == (sigaddset(&sigset, m_signalToClose))) {
        throwWithErrnoMessage("sigaddset()");
    }
    if((signal_fd = signalfd(-1, &sigset, 0)) < 0){
        throwWithErrnoMessage("signalfd()");
    }

    //Setting descriptors for pselect
    fd_set allset, rset;
    int maxfd;
    FD_ZERO(&allset);
    FD_SET(m_listenFd, &allset);
    FD_SET(signal_fd, &allset);
    timespec timeout;
    maxfd = (m_listenFd > signal_fd) ? (m_listenFd) : (signal_fd);
    ++maxfd;

    while(1){
        timeout.tv_sec = TIMEOUT_SEC;
        timeout.tv_nsec = TIMEOUT_NSEC;
        rset = allset;
        if(-1 == pselect(maxfd, &rset, NULL, NULL, &timeout, NULL)){
            closeConnections();
            throwWithErrnoMessage("pselect()");
        }

        if(FD_ISSET(signal_fd, &rset)){
            LogInfo("Got signal to close");
            signalfd_siginfo siginfo;
            ssize_t res;
            res = read(signal_fd, &siginfo, sizeof(siginfo));
            if(res <= 0){
                closeConnections();
                throwWithErrnoMessage("read()");
            }
            if((size_t)res != sizeof(siginfo)){
                closeConnections();
                LogError("couldn't read whole siginfo");
                ThrowMsg(DPL::Exception, "couldn't read whole siginfo");
            }
            if((int)siginfo.ssi_signo == m_signalToClose){
                LogInfo("Server thread got signal to close");
                closeConnections();
                return;
            } else {
                LogInfo("Got not handled signal");
            }
        }
        if(FD_ISSET(m_listenFd, &rset)){
            int client_fd;
            if(-1 == (client_fd = accept(m_listenFd, NULL, NULL))){
                closeConnections();
                throwWithErrnoMessage("accept()");
            }
            LogInfo("Got incoming connection");
            Connection_Info * connection = new Connection_Info(client_fd, (void *)this);
            int res;
            pthread_t client_thread;
            if((res = pthread_create(&client_thread, NULL, &connectionThread, connection)) < 0){
                delete connection;
                errno = res;
                closeConnections();
                throwWithErrnoMessage("pthread_create()");
            }
            addClientSocket(client_fd);
        }
    }
}

void * SecuritySocketService::connectionThread(void * data){
    pthread_detach(pthread_self());
    std::auto_ptr<Connection_Info> c (static_cast<Connection_Info *>(data));
    SecuritySocketService &t = *static_cast<SecuritySocketService *>(c->data);
    LogInfo("Starting connection thread");
    Try {
        t.connectionService(c->connfd);
    } Catch (DPL::Exception){
        LogError("Connection thread error : " << _rethrown_exception.DumpToString());
        t.removeClientSocket(c->connfd);
        close(c->connfd);
        return (void*)1;
    }
    LogInfo("Client serviced");
    return (void*)0;
}

void SecuritySocketService::connectionService(int fd){

    SocketConnection connector = SocketConnection(fd);
    std::string interfaceName, methodName;

    Try {
        connector.read(&interfaceName, &methodName);
    } Catch (SocketConnection::Exception::SocketConnectionException){
        LogError("Socket Connection read error");
        ReThrowMsg(DPL::Exception, "Socket Connection read error");
    }

    LogDebug("Got interface : " << interfaceName);
    LogDebug("Got method : " << methodName);

    if( m_callbackMap.find(interfaceName) == m_callbackMap.end()){
        LogError("Unknown interface : " << interfaceName);
        ThrowMsg(DPL::Exception, "Unknown interface : " << interfaceName);
    }

    if(m_callbackMap[interfaceName].find(methodName) == m_callbackMap[interfaceName].end()){
        LogError("Unknown method : " << methodName);
        ThrowMsg(DPL::Exception, "Unknown method");
    }

    if(m_callbackMap[interfaceName][methodName]->securityCallback != NULL){
        if(!m_callbackMap[interfaceName][methodName]->securityCallback(fd)){
            LogError("Security check returned false");
            ThrowMsg(DPL::Exception, "Security check returned false");
        }
    }

    LogInfo("Calling service");
    Try{
        m_callbackMap[interfaceName][methodName]->serviceCallback(&connector);
    } Catch (ServiceCallbackApi::Exception::ServiceCallbackException){
        LogError("Service callback error");
        ReThrowMsg(DPL::Exception, "Service callback error");
    }

    LogInfo("Removing client");
    removeClientSocket(fd);
    close(fd);

    LogInfo("Call served");

}

void SecuritySocketService::stop(){
    LogInfo("Stopping");
    if(-1 == close(m_listenFd))
        if(errno != ENOTCONN)
            throwWithErrnoMessage("close()");
    int returned_value;
    if((returned_value = pthread_kill(m_mainThread, m_signalToClose)) < 0){
        errno = returned_value;
        throwWithErrnoMessage("pthread_kill()");
    }
    pthread_join(m_mainThread, NULL);

    LogInfo("Stopped");
}

void SecuritySocketService::closeConnections(){

    int clientSocket;
    LogInfo("Closing client sockets");
    while(popClientSocket(&clientSocket)){
        if(-1 == close(clientSocket)){
            LogError("close() : " << strerror(errno));
        }
    }

    LogInfo("Connections closed");
}

void SecuritySocketService::deinitialize(){
    m_serverAddress.clear();

    LogInfo("Deinitialized");

}

#ifdef SOCKET_CONNECTION
DAEMON_REGISTER_SERVICE_MODULE(SecuritySocketService)
#endif
