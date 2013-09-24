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
 * @author      Zbigniew Jasinski (z.jasinski@samsung.com)
 * @author      Lukasz Kostyra (l.kostyra@partner.samsung.com)
 * @version     1.0
 * @brief       Implementation of password file buffer, used for serialization in password-manager.h
 */

#ifndef _PASSWORD_FILE_BUFFER_H_
#define _PASSWORD_FILE_BUFFER_H_

#include <stddef.h>
#include <vector>
#include <string>

#include <dpl/serialization.h>

namespace SecurityServer
{
    class PasswordFileBuffer: public IStream
    {
    public:
        PasswordFileBuffer();

        virtual void Read(size_t num, void *bytes);
        virtual void Write(size_t num, const void *bytes);

        void Save(const std::string &path);
        void Load(const std::string &path);

    private:
        typedef std::vector<char> DataBuffer;

        DataBuffer m_buffer;
        size_t m_bufferReadBytes;
    };
} //namespace SecurityServer

#endif
