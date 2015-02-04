/*
 *  Copyright (c) 2000 - 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        file-lock.h
 * @author      Sebastian Grabowski (s.grabowski@samsung.com)
 * @version     1.0
 * @brief       Implementation of simple file locking for a service
 */
/* vim: set ts=4 et sw=4 tw=78 : */

#pragma once

#include <boost/interprocess/sync/file_lock.hpp>

#include <dpl/exception.h>
#include <dpl/noncopyable.h>
#include <tzplatform_config.h>

namespace SecurityManager {

extern char const * const SERVICE_LOCK_FILE;

class FileLocker :
    public Noncopyable
{
public:
    class Exception
    {
    public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, LockFailed)
    };

    FileLocker(const std::string &lockFile, bool blocking = false);
    ~FileLocker();

    bool Locked();
    void Lock();
    void Unlock();

private:
    std::string m_lockFile;
    boost::interprocess::file_lock m_flock;
    bool m_blocking;
    bool m_locked;
};

} // namespace SecurityManager

