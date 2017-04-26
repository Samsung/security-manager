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
 * @file        client-common.cpp
 * @author      Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version     1.0
 * @brief       This file is implementation of client-common functions.
 */

#include <iostream>
#include <cxxabi.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/smack.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <unistd.h>

#include <dpl/log/log.h>
#include <dpl/serialization.h>
#include <dpl/singleton.h>

#include <message-buffer.h>

#include <protocols.h>

namespace {

void securityClientEnableLogSystem(void) {
    SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER_CLIENT");
}

} // namespace anonymous

namespace SecurityManager {

int try_catch(const std::function<int()>& func)
{
    try {
        return func();
    } catch (abi::__forced_unwind &) {
        throw;
    } catch (const Exception &e) {
        LogError("SecurityManager::Exception " << e.DumpToString());
        std::cerr << "SecurityManager::Exception " << e.DumpToString() << std::endl;
    } catch (const std::bad_alloc &e) {
        LogError("Memory allocation failed: " << e.what());
        std::cerr << "Memory allocation failed: " << e.what() << std::endl;
        return SECURITY_MANAGER_ERROR_MEMORY;
    } catch (const std::exception &e) {
        LogError("STD exception " << e.what());
        std::cerr << "STD exception " << e.what() << std::endl;
    } catch (...) {
        LogError("Unknown exception occurred");
        std::cerr << "Unknown exception occurred" << std::endl;
    }
    return SECURITY_MANAGER_ERROR_UNKNOWN;
}

} // namespace SecurityMANAGER

static void init_lib(void) __attribute__ ((constructor));
static void init_lib(void)
{
    securityClientEnableLogSystem();
}

static void fini_lib(void) __attribute__ ((destructor));
static void fini_lib(void)
{

}

