/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        naive_synchronization_object.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of SQL naive
 * synchronization object
 */
#include <stddef.h>
#include <dpl/db/naive_synchronization_object.h>
#include <dpl/thread.h>

namespace {
    unsigned int seed = time(NULL);
}

namespace DPL {
namespace DB {
void NaiveSynchronizationObject::Synchronize()
{
    // Sleep for about 10ms - 30ms
    Thread::MiliSleep(10 + rand_r(&seed) % 20);
}

void NaiveSynchronizationObject::NotifyAll()
{
    // No need to inform about anything
}
} // namespace DB
} // namespace DPL
