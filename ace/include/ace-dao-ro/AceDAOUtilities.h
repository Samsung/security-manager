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
 * @file       AceDAOUtil.h
 * @author     Grzegorz Krawczyk (g.krawczyk@samsung.com)
 * @version    0.1
 * @brief
 */

#ifndef WRT_ACE_DAO_UTILITIES_H_
#define WRT_ACE_DAO_UTILITIES_H_

#include <dpl/db/thread_database_support.h>
#include <ace-dao-ro/BaseAttribute.h>
#include <ace-dao-ro/PreferenceTypes.h>
#include <ace-dao-ro/VerdictTypes.h>
#include <orm_generator_ace.h>

namespace AceDB {

namespace AceDaoUtilities {

BaseAttribute::Type intToAttributeType(int val);
int attributeTypeToInt(BaseAttribute::Type type);
int preferenceToInt(PreferenceTypes p);
PreferenceTypes intToPreference(int p);
VerdictTypes intToVerdict(int v);
int verdictToInt(VerdictTypes v);
bool getSubjectByUri(const std::string &uri,
                     DPL::DB::ORM::ace::AceSubject::Row &row);
bool getResourceByUri(const std::string &uri,
                      DPL::DB::ORM::ace::AceDevCap::Row &row);

extern DPL::DB::ThreadDatabaseSupport m_databaseInterface;

}

}

#endif
