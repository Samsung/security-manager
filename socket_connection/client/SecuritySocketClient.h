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
 * @file        SecuritySocketClient.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Header of socket client class.
 */

#ifndef SECURITYSOCKETCLIENT_H_
#define SECURITYSOCKETCLIENT_H_

#include <memory>
#include <string>
#include <dpl/log/log.h>
#include "SocketConnection.h"

/* IMPORTANT:
 * Methods connect(), call() and disconnected() should be called one by one.
 * Between connect() and disconnect() you can use call() only once.
 * It is because of timeout on call, e.g. to avoid waiting for corrupted data.
 */

/* USAGE:
 * Class should be used according to this scheme:
 * SecuritySocketClient client("Interface Name");
 * (...)
 * client.connect();
 * client.call("Method name", in_arg1, in_arg2, ..., in_argN,
 *             out_arg1, out_arg2, ..., out_argM);
 * client.disconnect();
 * (...)
 *
 * input parameters of the call are passed with reference,
 * output ones are passed as pointers - parameters MUST be passed this way.
 *
 * Currently client supports serialization and deserialization of simple types
 * (int, char, float, unsigned), strings (std::string and char*) and
 * some STL containers (std::vector, std::list, std::map, std::pair).
 * Structures and classes are not (yet) supported.
 */

class SecuritySocketClient {
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, SecuritySocketClientException)
    };

    SecuritySocketClient(const std::string &interfaceName);
    void connect();
    void disconnect();

    void call(std::string methodName){
        make_call(m_interfaceName);
        make_call(methodName);
    }

    template<typename ...Args>
    void call(std::string methodName, const Args&... args){
        make_call(m_interfaceName);
        make_call(methodName);
        make_call(args...);
    }

private:
    template<typename T, typename ...Args>
    void make_call(const T& invalue, const Args&... args){
        make_call(invalue);
        make_call(args...);
    }

    template<typename T>
    void make_call(const T& invalue){
        Try {
            m_socketConnector->write(invalue);
        }
        Catch (SocketConnection::Exception::SocketConnectionException){
            LogError("Socket connection write error");
            ReThrowMsg(Exception::SecuritySocketClientException,"Socket connection write error");
        }
    }

    template<typename T, typename ...Args>
    void make_call(const T* invalue, const Args&... args){
        make_call(invalue);
        make_call(args...);
    }

    template<typename T>
    void make_call(const T* invalue){
        Try {
            m_socketConnector->write(invalue);
        }
        Catch (SocketConnection::Exception::SocketConnectionException){
            LogError("Socket connection write error");
            ReThrowMsg(Exception::SecuritySocketClientException,"Socket connection write error");
        }
    }

    template<typename T, typename ...Args>
    void make_call(T * outvalue, const Args&... args){
        make_call(outvalue);
        make_call(args...);
    }

    template<typename T>
    void make_call(T* outvalue){
        Try {
            m_socketConnector->read(outvalue);
        }
        Catch (SocketConnection::Exception::SocketConnectionException){
            LogError("Socket connection read error");
            ReThrowMsg(Exception::SecuritySocketClientException,"Socket connection read error");
        }
    }


private:
    void throwWithErrnoMessage(const std::string& specificInfo);
    std::string m_serverAddress;
    std::string m_interfaceName;
    std::unique_ptr<SocketConnection> m_socketConnector;
    int m_socketFd;
};

#endif /* SECURITYSOCKETCLIENT_H_ */
