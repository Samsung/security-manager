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
 * @file       AceDaoConversions.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @author     Grzegorz Krawczyk (g.krawczyk@samsung.com)
 * @version    0.1
 * @brief
 */

#include <openssl/md5.h>
#include <dpl/foreach.h>

#include <ace-dao-ro/AceDAOConversions.h>

namespace AceDB {

DPL::String AceDaoConversions::convertToHash(const BaseAttributeSet &attributes)
{
    unsigned char attrHash[MD5_DIGEST_LENGTH];
    std::string attrString;
    FOREACH(it, attributes) {
        // [CR] implementation of it->toString() is not secure, 24.03.2010
        attrString.append((*it)->toString());
    }

    MD5((unsigned char *) attrString.c_str(), attrString.length(), attrHash);

    char attrHashCoded[MD5_DIGEST_LENGTH*2 + 1];
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        sprintf(&attrHashCoded[i << 1],
                "%02X",
                static_cast<int>(attrHash[i]));
    }
    return DPL::FromASCIIString(attrHashCoded);
}


}
