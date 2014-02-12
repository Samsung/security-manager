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
 * @file        password-file-buffer.h
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of PasswordFileBuffer, used for serialization in PasswordFile class
 */

#include <password-file-buffer.h>

#include <fstream>
#include <iterator>

#include <dpl/log/log.h>
#include <dpl/fstream_accessors.h>

#include <security-server.h>
#include <password-exception.h>

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

namespace SecurityServer
{
    PasswordFileBuffer::PasswordFileBuffer(): m_bufferReadBytes(0) {}

    void PasswordFileBuffer::Read(size_t num, void *bytes)
    {
        if(m_buffer.empty()) {
            LogError("Buffer doesn't contain any data.");
            Throw(PasswordException::NoData);
        }

        if((m_bufferReadBytes + num) > m_buffer.size()) {
            LogError("Not enough buffer to read " << num << " data.");
            Throw(PasswordException::OutOfData);
        }

        void* ret = memcpy(bytes, &m_buffer[m_bufferReadBytes], num);

        if(ret == 0) {
            LogError("Failed to read " << num << " bytes.");
            Throw(PasswordException::MemoryError);
        }

        m_bufferReadBytes += num;
    }

    void PasswordFileBuffer::Write(size_t num, const void *bytes)
    {
        const char* buffer = static_cast<const char*>(bytes);
        std::copy(buffer, buffer+num, std::back_inserter(m_buffer));
    }

    void PasswordFileBuffer::Save(const std::string &path)
    {
        std::ofstream file(path, std::ofstream::trunc);

        if(!file.good()) {
            LogError("Error while opening file stream.");
            Throw(PasswordException::FStreamOpenError);
        }

        file.write(m_buffer.data(), m_buffer.size());
        if(!file) {
            LogError("Failed to write data.");
            Throw(PasswordException::FStreamWriteError);
        }

        file.flush();
        fsync(DPL::FstreamAccessors<std::ofstream>::GetFd(file)); // flush kernel space buffer
        file.close();
    }

    void PasswordFileBuffer::Load(const std::string &path)
    {
        std::ifstream file(path, std::ifstream::binary);

        if(!file.good()) {
            LogError("Error while opening file stream.");
            Throw(PasswordException::FStreamOpenError);
        }

        //reset read bytes counter
        m_bufferReadBytes = 0;

        m_buffer.assign(std::istreambuf_iterator<char>(file),
                        std::istreambuf_iterator<char>());

        if(!file) {
            LogError("Failed to read data. Failbit: " << file.fail() << ", Badbit: " << file.bad());
            Throw(PasswordException::FStreamReadError);
        }
    }

} //namespace SecurityServer
