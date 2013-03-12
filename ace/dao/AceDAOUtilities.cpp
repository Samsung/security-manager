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
 * @file       AceDaoReadOnly.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @author     Grzegorz Krawczyk (g.krawczyk@samsung.com)
 * @version    0.1
 * @brief
 */

#include <openssl/md5.h>
#include <dpl/assert.h>
#include <dpl/foreach.h>

#include <ace-dao-ro/AceDatabase.h>
#include <ace-dao-ro/AceDAOUtilities.h>
#include <ace-dao-ro/AceDAOReadOnly.h>

namespace AceDB {

namespace {
const char* ACE_DB_DATABASE = "/opt/dbspace/.ace.db";
DPL::DB::SqlConnection::Flag::Type ACE_DB_FLAGS =
    DPL::DB::SqlConnection::Flag::UseLucene;
}

DPL::DB::ThreadDatabaseSupport AceDaoUtilities::m_databaseInterface(
        ACE_DB_DATABASE, ACE_DB_FLAGS);

BaseAttribute::Type AceDaoUtilities::intToAttributeType(int val)
{
    switch (val) {
    case 0:
        return BaseAttribute::Type::Subject;
    case 1:
        return BaseAttribute::Type::Environment;
    case 2:
        return BaseAttribute::Type::Resource;
    case 3:
        return BaseAttribute::Type::FunctionParam;
    case 4:
        return BaseAttribute::Type::WidgetParam;

    default:
        Assert(0 && "Unknown Attribute type value");
        return BaseAttribute::Type::Subject; //remove compilation warrning
    }
}

int AceDaoUtilities::attributeTypeToInt(BaseAttribute::Type type)
{
    // we cannot cast enum -> int because this cast will be removed from next c++ standard
    switch (type) {
    case BaseAttribute::Type::Subject:
        return 0;
    case BaseAttribute::Type::Environment:
        return 1;
    case BaseAttribute::Type::Resource:
        return 2;
    case BaseAttribute::Type::FunctionParam:
        return 3;
    case BaseAttribute::Type::WidgetParam:
        return 4;

    default:
        Assert(0 && "Unknown Attribute type!");
        return 0; //remove compilation warrning
    }
}

int AceDaoUtilities::preferenceToInt(PreferenceTypes p)
{
    switch (p) {
        case PreferenceTypes::PREFERENCE_PERMIT:
        return 1;
    case PreferenceTypes::PREFERENCE_DENY:
        return 0;
    case PreferenceTypes::PREFERENCE_BLANKET_PROMPT:
        return 2;
    case PreferenceTypes::PREFERENCE_SESSION_PROMPT:
        return 3;
    case PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT:
        return 4;

    default:
        return -1;
    }
}

PreferenceTypes AceDaoUtilities::intToPreference(int p)
{
    switch (p) {
    case 1:
        return PreferenceTypes::PREFERENCE_PERMIT;
    case 0:
        return PreferenceTypes::PREFERENCE_DENY;
    case 2:
        return PreferenceTypes::PREFERENCE_BLANKET_PROMPT;
    case 3:
        return PreferenceTypes::PREFERENCE_SESSION_PROMPT;
    case 4:
        return PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT;

    default:
        return PreferenceTypes::PREFERENCE_DEFAULT;
    }
}

VerdictTypes AceDaoUtilities::intToVerdict(int v)
{
    switch (v) {
    case -1:
        return VerdictTypes::VERDICT_UNKNOWN;
    case 0:
        return VerdictTypes::VERDICT_DENY;
    case 1:
        return VerdictTypes::VERDICT_PERMIT;
    case 2:
        return VerdictTypes::VERDICT_INAPPLICABLE;

    default:
        Assert(0 && "Cannot convert int to verdict");
        return VerdictTypes::VERDICT_UNKNOWN; // remove compile warrning
    }
}

int AceDaoUtilities::verdictToInt(VerdictTypes v)
{
    switch (v) {
    case VerdictTypes::VERDICT_UNKNOWN:
        return -1;
    case VerdictTypes::VERDICT_DENY:
        return 0;
    case VerdictTypes::VERDICT_PERMIT:
        return 1;
    case VerdictTypes::VERDICT_INAPPLICABLE:
        return 2;

    default:
        Assert(0 && "Unknown Verdict value");
        return -1; // remove compile warrning
    }
}

bool AceDaoUtilities::getSubjectByUri(const std::string &uri,
                                      DPL::DB::ORM::ace::AceSubject::Row &row)
{
    using namespace DPL::DB::ORM;
    using namespace DPL::DB::ORM::ace;
    ACE_DB_SELECT(select, AceSubject, &m_databaseInterface);
    select->Where(Equals<AceSubject::id_uri>(DPL::FromUTF8String(uri)));
    std::list<AceSubject::Row> rows = select->GetRowList();
    if (rows.empty()) {
        return false;
    }

    row = rows.front();
    return true;
}

bool AceDaoUtilities::getResourceByUri(const std::string &uri,
                                       DPL::DB::ORM::ace::AceDevCap::Row &row)
{
    using namespace DPL::DB::ORM;
    using namespace DPL::DB::ORM::ace;
    ACE_DB_SELECT(select, AceDevCap, &m_databaseInterface);
    select->Where(Equals<AceDevCap::id_uri>(DPL::FromUTF8String(uri)));
    std::list<AceDevCap::Row> rows = select->GetRowList();
    if (rows.empty()) {
        return false;
    }

    row = rows.front();
    return true;
}


}
