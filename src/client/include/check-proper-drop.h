/*
 *  Copyright (c) 2015-2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        check-proper-drop.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Definition of proper privilege dropping check utilities
 */

#pragma once

#include <dpl/exception.h>

#include <unistd.h>
#include <proc/readproc.h>

#include <vector>

namespace SecurityManager {

class CheckProperDrop {
public:
    class Exception {
    public:
        DECLARE_EXCEPTION_TYPE(SecurityManager::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, ProcError)
        DECLARE_EXCEPTION_TYPE(Base, CapError)
    };

    ~CheckProperDrop();
    CheckProperDrop(pid_t pid = getpid()) : m_pid(pid) {};

    /**
     * Fetch credentials of the process and all its threads.
     * Must be called before checkThreads().
     */
    void getThreads();

    /**
     * Check whether all threads of the process has properly aligned
     * credentials:
     * - uids
     * - gids
     * - capabilities
     * - Smack labels
     *
     * It will terminate the calling process if any thread has different
     * value than the other threads. This prevents security risks associated
     * with improperly dropped privileges during application launch.
     */
    bool checkThreads();

private:
    pid_t m_pid;
    proc_t *m_proc = nullptr;
    std::vector<proc_t*> m_threads;
};

} // namespace SecurityManager
