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
/**
 *
 *
 * @file       BaseAttribute.cpp
 * @author     Lukasz Marek (l.marek@samsung.com)
 * @version    0.1
 * @brief
 */

#include <sstream>
#include <string>

#include <ace-dao-ro/BaseAttribute.h>

namespace AceDB {

const char* BaseAttribute::typeToString(Type type)
{
    const char * ret = NULL;
    switch (type) {
    case Type::Resource:
        ret = "resource";
        break;
    case Type::Subject:
        ret = "subject";
        break;
    case Type::Environment:
        ret = "environment";
        break;
    default:
        ret = "unknown type";
        break;
    }

    return ret;
}

std::string BaseAttribute::toString() const
{
    std::string ret;
    const char * SEPARATOR = ";";

    ret.append(m_name);
    ret.append(SEPARATOR);
    ret.append(typeToString(m_typeId));
    ret.append(SEPARATOR);
    if (m_undetermindState) {
        ret.append("true");
    } else {
        ret.append("false");
    }
    ret.append(SEPARATOR);
    for (std::list<std::string>::const_iterator it = value.begin();
         it != value.end();
         ++it) {
        std::stringstream num;
        num << it->size();
        ret.append(num.str());
        ret.append(SEPARATOR);
        ret.append(*it);
        ret.append(SEPARATOR);
    }

    return ret;
}

}
