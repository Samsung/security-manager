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
 * @file        SocketStream.cpp
 * @author      Zofia Abramowska (z.abramowska@samsung.com)
 * @version     1.0
 * @brief       Implementation of socket stream class
 */


#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <cstring>
#include <dpl/log/log.h>
#include "SocketStream.h"

#define READ_TIEMOUT_SEC 1
#define READ_TIMEUOT_NSEC 0
#define WRITE_TIMEOUT_SEC 0
#define WRITE_TIMEOUT_NSEC 100000000
#define MAX_BUFFER 10240

void SocketStream::throwWithErrnoMessage(std::string function_name){
    LogError(function_name << " : " << strerror(errno));
    ThrowMsg(Exception::SocketStreamException, function_name << " : " << strerror(errno));
}

void SocketStream::Read(size_t num, void * bytes){

    if(NULL == bytes){
        LogError("Null pointer to buffer");
        ThrowMsg(Exception::SocketStreamException, "Null pointer to buffer");
    }
    
    m_bytesRead += num;
    
    if(m_bytesRead > MAX_BUFFER){
        LogError("Too big buffer requested!");
        ThrowMsg(Exception::SocketStreamException, "Too big buffer requested!");
    }

    char part_buffer[MAX_BUFFER];
    std::string whole_buffer;

    fd_set rset, allset;
    int max_fd;
    ssize_t bytes_read = 0, bytes_to_read = (ssize_t) num;

    timespec timeout;

    max_fd = m_socketFd;
    ++max_fd;

    FD_ZERO(&allset);
    FD_SET(m_socketFd, &allset);

    int returned_value;

    while(bytes_to_read != 0){
        timeout.tv_sec = READ_TIEMOUT_SEC;
        timeout.tv_nsec = READ_TIMEUOT_NSEC;
        rset = allset;

        if(-1 == (returned_value = pselect(max_fd, &rset, NULL, NULL, &timeout, NULL))){
            if(errno == EINTR) continue;
            throwWithErrnoMessage("pselect()");
        }
        if(0 == returned_value){
            //This means pselect got timedout
            //This is not a proper behavior in reading data from UDS
            //And could mean we got corrupted connection
            LogError("Couldn't read whole data");
            ThrowMsg(Exception::SocketStreamException, "Couldn't read whole data");
        }
        if(FD_ISSET(m_socketFd, &rset)){
            bytes_read = read(m_socketFd, part_buffer, num);
            if(bytes_read <= 0){
                if(errno == ECONNRESET || errno == ENOTCONN || errno == ETIMEDOUT){
                    LogInfo("Connection closed : " << strerror(errno));
                    ThrowMsg(Exception::SocketStreamException,
                            "Connection closed : " << strerror(errno) << ". Couldn't read whole data");
                }else if (errno != EAGAIN && errno != EWOULDBLOCK){
                    throwWithErrnoMessage("read()");
                }
            }

            whole_buffer.append(part_buffer, bytes_read);
            bytes_to_read-=bytes_read;
            bytes_read = 0;
            continue;
        }

    }
    memcpy(bytes, whole_buffer.c_str(), num);
}

void SocketStream::Write(size_t num, const void * bytes){

    if(NULL == bytes){
        LogError("Null pointer to buffer");
        ThrowMsg(Exception::SocketStreamException, "Null pointer to buffer");
    }
    
    m_bytesWrote += num;
    
    if(m_bytesWrote > MAX_BUFFER){
        LogError("Too big buffer requested!");
        ThrowMsg(Exception::SocketStreamException, "Too big buffer requested!");
    }

    fd_set wset, allset;
    int max_fd;

    timespec timeout;

    max_fd = m_socketFd;
    ++max_fd;

    FD_ZERO(&allset);
    FD_SET(m_socketFd, &allset);

    int returned_value;

    int write_res, bytes_to_write = num;
    unsigned int current_offset = 0;

    while(current_offset != num){
        timeout.tv_sec = WRITE_TIMEOUT_SEC;
        timeout.tv_nsec = WRITE_TIMEOUT_NSEC;
        wset = allset;

        if(-1 == (returned_value = pselect(max_fd, NULL, &wset, NULL, &timeout, NULL))){
            if(errno == EINTR) continue;
            throwWithErrnoMessage("pselect()");
        }

        if(FD_ISSET(m_socketFd, &wset)){
            if(-1 == (write_res = write(m_socketFd, reinterpret_cast<const char *>(bytes) + current_offset, bytes_to_write))){
                if(errno == ECONNRESET || errno == EPIPE){
                    LogInfo("Connection closed : " << strerror(errno));
                    ThrowMsg(Exception::SocketStreamException,
                            "Connection closed : " << strerror(errno) << ". Couldn't write whole data");

                }else if(errno != EAGAIN && errno != EWOULDBLOCK){
                    throwWithErrnoMessage("write()");
                }
            }
            current_offset += write_res;
            bytes_to_write -= write_res;
        }
    }
}
