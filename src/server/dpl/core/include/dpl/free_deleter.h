/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        free_deleter.h
 * @author      Pawel Czajkowski (p.czajkowski@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file deleter with use std::free()
 */
#ifndef FREE_DELETER_H
#define FREE_DELETER_H

#include <cstdlib>
namespace DPL
{
struct free_deleter
{
    void operator()(void *p) { std::free(p); }
};
}// DPL
#endif // FREE_DELETER_H
