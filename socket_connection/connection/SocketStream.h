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
 * @file        SocketStream.h
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Header of socket stream class.
 */

#ifndef SOCKETSTREAM_H_
#define SOCKETSTREAM_H_

#include <string>
#include <sys/socket.h>
#include <sys/select.h>
#include <dpl/serialization.h>
#include <dpl/log/log.h>

/*
 * This class implements binary read/write from socket used for DPL serialization and deserialization
 * It can read or write buffers of max *total* size 10kB.
 * I does not maintain socket descriptor.
 */

/*
 * Throws SocketStreamException when buffer is null or its size exceeds max size or when
 * there is an error during read or write.
 */



class SocketStream : public DPL::IStream {
public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, SocketStreamException)
    };

    explicit SocketStream(int socket_fd) : m_socketFd(socket_fd), 
                                           m_bytesRead(0),
                                           m_bytesWrote(0)
    {
        LogInfo("Created");
    }
    void Read(size_t num, void * bytes);
    void Write(size_t num, const void * bytes);
private:
    void throwWithErrnoMessage(std::string specificInfo);
    int m_socketFd;
    int m_bytesRead;
    int m_bytesWrote;
};

#endif /* SOCKETSTREAM_H_ */
