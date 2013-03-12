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
/*
 * @file        SocketConnection.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       This file is a header of Socket Connection class with implemented templates
 */

#ifndef SOCKETCONNECTION_H_
#define SOCKETCONNECTION_H_

#include <dpl/serialization.h>
#include <dpl/log/log.h>
#include <new>
#include "SocketStream.h"

/*
 * This class implements interface for generic read and write from given socket.
 * It does not maintain socket descriptor, so any connecting and disconnecting should be
 * done above calls to this class.
 */

/*
 * Throws SocketConnectionException when read/write will not succeed or if any bad allocation
 * exception occurs during read.
 */

class SocketConnection {

public:

    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, SocketConnectionException)
    };

    explicit SocketConnection(int socket_fd) : m_socketStream(socket_fd){
        LogInfo("Created");
    }

    template<typename T, typename ...Args>
    void read(T* out, const Args&... args ){
        read(out);
        read(args...);
    }

    template<typename T>
    void read(T* out){
        Try {
            DPL::Deserialization::Deserialize(m_socketStream, *out);
        }

        Catch (std::bad_alloc){
            LogError("Bad allocation error");
            ThrowMsg(Exception::SocketConnectionException, "Bad allocation error");
        }

        Catch (SocketStream::Exception::SocketStreamException) {
            LogError("Socket stream error");
            ReThrowMsg(Exception::SocketConnectionException, "Socket stream error");
        }
    }

    template<typename T, typename ...Args>
    void write(const T& in, const Args&... args){
        write(in);
        write(args...);
    }

    template<typename T>
    void write(const T& in){
        Try {
            DPL::Serialization::Serialize(m_socketStream, in);
        } Catch (SocketStream::Exception::SocketStreamException) {
            LogError("Socket stream error");
            ReThrowMsg(Exception::SocketConnectionException, "Socket stream error");
        }
    }

    template<typename T, typename ...Args>
    void write(const T* in, const Args&... args){
        write(in);
        write(args...);
    }

    template<typename T>
        void write(const T* in){
            Try {
                DPL::Serialization::Serialize(m_socketStream, in);
            } Catch (SocketStream::Exception::SocketStreamException) {
                LogError("Socket stream error");
                ReThrowMsg(Exception::SocketConnectionException, "Socket stream error");
            }
        }

private:
    SocketStream m_socketStream;
};

#endif /* SOCKETCONNECTION_H_ */
