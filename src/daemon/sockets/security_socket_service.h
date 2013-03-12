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
 * @file        security_socket_service.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Header of socket server class
 */

#ifndef SECURITY_SOCKET_SERVICE_H_
#define SECURITY_SOCKET_SERVICE_H_

#include <map>
#include <list>
#include <memory>
#include <mutex>
#include <pthread.h>
#include <security_daemon.h>
#include <SocketConnection.h>
#include <callback_api.h>

class SecuritySocketService : public SecurityDaemon::DaemonService {

private:

  virtual void initialize();
  virtual void start();
  virtual void stop();
  virtual void deinitialize();


private:

    //Function for registering callback with given interface and method name and possibly security check callback
    void registerServiceCallback(const std::string& interfaceName,
                                 const std::string& methodName,
                                 socketServerCallback serviceCallback,
                                 securityCheck securityCallback = NULL);
    //Thread function for server
    static void * serverThread(void *);
    //Main function for server
    void mainLoop();
    //Thread function for connection serving
    static void * connectionThread(void *);
    //Main function for connection serving
    void connectionService(int fd);
    //closing all connections
    void closeConnections();
    //logs an error and throws an exception with message containing errno message
    void throwWithErrnoMessage(const std::string &specificInfo);

    //concurrency safe methods for client socket list - add, remove and pop (with returned value)
    void addClientSocket(int clientThread);
    void removeClientSocket(int clientThread);
    bool popClientSocket(int* clientThread);

    //Address of socket server
    std::string m_serverAddress;
    //Signal used for informing threads to stop
    int m_signalToClose;
    //Socket for listening
    int m_listenFd;
    //Number of main thread
    pthread_t m_mainThread;
    //Numbers of all created threads for connections
    std::list<int> m_clientSocketList;

    //Thread list mutex
    std::mutex m_clientSocketListMutex;

    //Structure for callback maps
    class ServiceCallback
    {
    public:
        ServiceCallback(socketServerCallback ser, securityCheck sec) : serviceCallback(ser), securityCallback(sec){}
        socketServerCallback serviceCallback;
        securityCheck securityCallback;
    };

    typedef std::shared_ptr<ServiceCallback> ServiceCallbackPtr;
    //Map for callback methods, key is a method name and value is a callback to method
    typedef std::map<std::string, ServiceCallbackPtr> ServiceMethodCallbackMap;
    //Map for interface methods, key is an interface name and value is a map of available methods with callbacks
    std::map<std::string, ServiceMethodCallbackMap> m_callbackMap;

    //Structure passed to connection thread
    struct Connection_Info{
        Connection_Info(int fd, void * data) : connfd(fd), data(data)
        {}
        int connfd;
        void * data;
    };

};

#endif /* SECURITY_SOCKET_SERVICE_H_ */
