/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        utils.h
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Utility macros and templates
 */

#pragma once

#include <functional>
#include <memory>

namespace SecurityManager {

// Pointer
template<typename T>
std::unique_ptr<T> makeUnique(T *ptr)
{
    return std::unique_ptr<T>(ptr);
}

// Pointer & deleter func
template<typename T, typename F>
std::unique_ptr<T, F> makeUnique(T *ptr, F func)
{
    return std::unique_ptr<T, F>(ptr, func);
}

// Array - borrowed from C++14
template<typename T>
std::unique_ptr<T> makeUnique(size_t size)
{
    return std::unique_ptr<T>(new typename std::remove_extent<T>::type[size]);
}

} /* namespace SecurityManager */
