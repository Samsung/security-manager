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

#include "PopupSerializer.h"
#include <dpl/scoped_array.h>

namespace PopupSerializer {

void appendArg(int arg, DPL::BinaryQueue &buffer)
{
    size_t argSize = sizeof(arg);
    buffer.AppendCopy(&argSize, sizeof(argSize));
    buffer.AppendCopy(&arg, sizeof(arg));
}

void appendArg(const std::string &arg, DPL::BinaryQueue &buffer)
{
    size_t argSize = arg.size();
    buffer.AppendCopy(&argSize, sizeof(argSize));
    buffer.AppendCopy(arg.c_str(), argSize);
}

int getIntArg(DPL::BinaryQueue &buffer)
{
    int result;
    size_t argSize;
    buffer.FlattenConsume(&argSize, sizeof(argSize));
    buffer.FlattenConsume(&result, argSize);
    //TODO: what if argSize != sizeof(int)
    //This should not be problem if this is run on the same machine.
    return result;
}

std::string getStringArg(DPL::BinaryQueue &buffer)
{
    std::string::size_type size;
    buffer.FlattenConsume(&size, sizeof(size));
    DPL::ScopedArray<char> str(new char[size]);
    buffer.FlattenConsume(str.Get(), size);
    return std::string(str.Get(), str.Get() + size);
}

}