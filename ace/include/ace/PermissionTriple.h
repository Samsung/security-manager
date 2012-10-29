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
//
//
//
//  @ Project : Access Control Engine
//  @ File Name : PermissionTriple.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#if !defined(_PERMISSION_TRIPLE_H)
#define _PERMISSION_TRIPLE_H

#include <string>
#include <list>
#include <ace-dao-ro/PreferenceTypes.h>
#include <ace-dao-ro/BasePermission.h>

typedef AceDB::BasePermission PermissionTriple;
typedef AceDB::BasePermissionList PermissionList;

struct GeneralSetting
{
    GeneralSetting(const std::string& resourceName,
            AceDB::PreferenceTypes accessAllowed) : generalSettingName(resourceName),
        access(accessAllowed)
    {
    }
    std::string generalSettingName;
    AceDB::PreferenceTypes access;
};

#endif  //_PERMISSION_TRIPLE_H
