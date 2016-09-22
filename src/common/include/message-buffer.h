/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
 * @file        message-buffer.h
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       Implementatin of MessageBuffer.
 */

#pragma once

#include <vector>

#include <dpl/binary_queue.h>
#include <dpl/exception.h>
#include <dpl/serialization.h>

namespace SecurityManager {

typedef std::vector<unsigned char> RawBuffer;

class MessageBuffer : public SecurityManager::IStream {
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, OutOfData)
    };

    MessageBuffer()
      : m_bytesLeft(0)
    {}

    void Push(const RawBuffer &data);

    RawBuffer Pop();

    bool Ready();

    virtual void Read(size_t num, void *bytes);

    virtual void Write(size_t num, const void *bytes);

protected:

    inline void CountBytesLeft() {
        if (m_bytesLeft > 0)
            return;  // we already counted m_bytesLeft nothing to do

        if (m_buffer.Size() < sizeof(size_t))
            return;  // we cannot count m_bytesLeft because buffer is too small

        m_buffer.FlattenConsume(&m_bytesLeft, sizeof(size_t));
    }

    size_t m_bytesLeft;
    SecurityManager::BinaryQueue m_buffer;
};

} // namespace SecurityManager
