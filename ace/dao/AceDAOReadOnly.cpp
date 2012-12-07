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
 * @file       AceDAOReadOnlyReadOnly.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @author     Grzegorz Krawczyk (g.krawczyk@samsung.com)
 * @version    0.1
 * @brief
 */

#include <list>
#include <utility>

#include <ace-dao-ro/AceDAOReadOnly.h>
#include <ace-dao-ro/AceDAOUtilities.h>
#include <ace-dao-ro/AceDAOConversions.h>
#include <ace-dao-ro/AceDatabase.h>
#include <dpl/foreach.h>

using namespace DPL::DB::ORM;
using namespace DPL::DB::ORM::ace;
using namespace AceDB::AceDaoUtilities;
using namespace AceDB::AceDaoConversions;

namespace AceDB {

static const int DB_ALLOW_ALWAYS = 0;
static const int DB_ALLOW_FOR_SESSION = 1;
static const int DB_ALLOW_THIS_TIME = 2;
static const int DB_DENY_ALWAYS = 3;
static const int DB_DENY_FOR_SESSION = 4;
static const int DB_DENY_THIS_TIME = 5;

static const int DB_APP_UNKNOWN = 0;
static const int DB_APP_WAC20 = 1;
static const int DB_APP_TIZEN = 2;

int AceDAOReadOnly::promptDecisionToInt(PromptDecision decision)
{
    if (PromptDecision::ALLOW_ALWAYS == decision) {
        return DB_ALLOW_ALWAYS;
    } else if (PromptDecision::DENY_ALWAYS == decision) {
        return DB_DENY_ALWAYS;
    } else if (PromptDecision::ALLOW_THIS_TIME == decision) {
        return DB_ALLOW_THIS_TIME;
    } else if (PromptDecision::DENY_THIS_TIME == decision) {
        return DB_DENY_THIS_TIME;
    } else if (PromptDecision::ALLOW_FOR_SESSION == decision) {
        return DB_ALLOW_FOR_SESSION;
    }
    // DENY_FOR_SESSION
    return DB_DENY_FOR_SESSION;
}

PromptDecision AceDAOReadOnly::intToPromptDecision(int dec) {
    if (dec == DB_ALLOW_ALWAYS) {
        return PromptDecision::ALLOW_ALWAYS;
    } else if (dec == DB_DENY_ALWAYS) {
        return PromptDecision::DENY_ALWAYS;
    } else if (dec == DB_ALLOW_THIS_TIME) {
        return PromptDecision::ALLOW_THIS_TIME;
    } else if (dec == DB_DENY_THIS_TIME) {
        return PromptDecision::DENY_THIS_TIME;
    } else if (dec == DB_ALLOW_FOR_SESSION) {
        return PromptDecision::ALLOW_FOR_SESSION;
    }
    // DB_DENY_FOR_SESSION
    return PromptDecision::DENY_FOR_SESSION;
}

int AceDAOReadOnly::appTypeToInt(AppTypes app_type)
{
    switch (app_type) {
    case AppTypes::Unknown:
        return DB_APP_UNKNOWN;
    case AppTypes::WAC20:
        return DB_APP_WAC20;
    case AppTypes::Tizen:
        return DB_APP_TIZEN;
    default:
        return DB_APP_UNKNOWN;
    }

}

AppTypes AceDAOReadOnly::intToAppType(int app_type)
{
    switch (app_type) {
    case DB_APP_UNKNOWN:
        return AppTypes::Unknown;
    case DB_APP_WAC20:
        return AppTypes::WAC20;
    case DB_APP_TIZEN:
        return AppTypes::Tizen;
    default:
        return AppTypes::Unknown;
    }
}

void AceDAOReadOnly::attachToThreadRO()
{
    AceDaoUtilities::m_databaseInterface.AttachToThread(
        DPL::DB::SqlConnection::Flag::RO);
}

void AceDAOReadOnly::attachToThreadRW()
{
    AceDaoUtilities::m_databaseInterface.AttachToThread(
        DPL::DB::SqlConnection::Flag::RW);
}

void AceDAOReadOnly::detachFromThread()
{
    AceDaoUtilities::m_databaseInterface.DetachFromThread();
}

OptionalCachedPromptDecision AceDAOReadOnly::getPromptDecision(
    WidgetHandle widgetHandle,
    int ruleId)
{
    Try {
        // get matching subject verdict
        ACE_DB_SELECT(select, AcePromptDecision, &AceDaoUtilities::m_databaseInterface);

        select->Where(
            And(
                Equals<AcePromptDecision::rule_id>(ruleId),
                Equals<AcePromptDecision::app_id>(widgetHandle)));

        std::list<AcePromptDecision::Row> rows = select->GetRowList();
        if (rows.empty()) {
            return OptionalCachedPromptDecision();
        }

        AcePromptDecision::Row row = rows.front();
        CachedPromptDecision decision;
        decision.decision = intToPromptDecision(row.Get_decision());
        decision.session = row.Get_session();

        return OptionalCachedPromptDecision(decision);
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getPromptDecision");
    }
}

void AceDAOReadOnly::getAttributes(BaseAttributeSet *attributes)
{
    if (NULL == attributes) {
        LogError("NULL pointer");
        return;
    }
    attributes->clear();
    std::string aname;
    int type;
    Try {
        ACE_DB_SELECT(select, AceAttribute, &AceDaoUtilities::m_databaseInterface);
        typedef std::list<AceAttribute::Row> RowList;
        RowList list = select->GetRowList();

        FOREACH(i, list) {
            BaseAttributePtr attribute(new BaseAttribute());
            DPL::String name = i->Get_name();
            aname = DPL::ToUTF8String(name);
            type = i->Get_type();

            attribute->setName(&aname);
            attribute->setType(intToAttributeType(type));
            attributes->insert(attribute);
        }
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getAttributes");
    }
}

OptionalExtendedPolicyResult AceDAOReadOnly::getPolicyResult(
        const BaseAttributeSet &attributes)
{

    auto attrHash = convertToHash(attributes);
    return getPolicyResult(attrHash);
}

OptionalExtendedPolicyResult AceDAOReadOnly::getPolicyResult(
    const DPL::String &attrHash)
{
    Try {
        // get matching subject verdict
        ACE_DB_SELECT(select, AcePolicyResult, &AceDaoUtilities::m_databaseInterface);
        Equals<AcePolicyResult::hash> e1(attrHash);
        select->Where(e1);

        std::list<AcePolicyResult::Row> rows = select->GetRowList();
        if (rows.empty()) {
            return OptionalExtendedPolicyResult();
        }

        AcePolicyResult::Row row = rows.front();
        int decision = row.Get_decision();
        ExtendedPolicyResult res;
        res.policyResult = PolicyResult::deserialize(decision);
        res.ruleId = row.Get_rule_id();
        return OptionalExtendedPolicyResult(res);
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getVerdict");
    }
}

PreferenceTypes AceDAOReadOnly::getDevCapSetting(const std::string &resource)
{
    Try {
        AceDevCap::Row row;
        if (!getResourceByUri(resource, row)) {
            return PreferenceTypes::PREFERENCE_DEFAULT;
        }
        return intToPreference(row.Get_general_setting());
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getResourceSetting");
    }
}

void AceDAOReadOnly::getDevCapSettings(PreferenceTypesMap *globalSettingsMap)
{
    if (NULL == globalSettingsMap) {
        LogError("Null pointer");
        return;
    }
    globalSettingsMap->clear();
    Try {
        ACE_DB_SELECT(select, AceDevCap, &AceDaoUtilities::m_databaseInterface);
        typedef std::list<AceDevCap::Row> RowList;
        RowList list = select->GetRowList();

        FOREACH(i, list) {
            PreferenceTypes p = intToPreference(i->Get_general_setting());
            globalSettingsMap->insert(make_pair(DPL::ToUTF8String(
                i->Get_id_uri()), p));
        }
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getResourceSettings");
    }
}

void AceDAOReadOnly::getWidgetDevCapSettings(BasePermissionList *outputList)
{
    if (NULL == outputList) {
        LogError("NULL pointer");
        return;
    }
    outputList->clear();
    Try {
        std::string resourceName;
        PreferenceTypes allowAccess;

        ACE_DB_SELECT(select,
                      AceWidgetDevCapSetting,
                      &AceDaoUtilities::m_databaseInterface);

        typedef std::list<AceWidgetDevCapSetting::Row> RowList;
        RowList list = select->GetRowList();

        // TODO JOIN
        FOREACH(i, list) {
            int app_id = i->Get_app_id();
            int res_id = i->Get_resource_id();

            ACE_DB_SELECT(resourceSelect, AceDevCap, &AceDaoUtilities::m_databaseInterface);
            resourceSelect->Where(Equals<AceDevCap::resource_id>(res_id));
            AceDevCap::Row rrow = resourceSelect->GetSingleRow();

            resourceName = DPL::ToUTF8String(rrow.Get_id_uri());

            if (!resourceName.empty()) {
                allowAccess = intToPreference(i->Get_access_value());
                outputList->push_back(
                    BasePermission(app_id,
                    resourceName,
                    allowAccess));
            }
        }
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to findUserSettings");
    }
}

PreferenceTypes AceDAOReadOnly::getWidgetDevCapSetting(
        const std::string &resource,
        WidgetHandle handler)
{
    Try {
        AceDevCap::Row rrow;
        if (!getResourceByUri(resource, rrow)) {
            return PreferenceTypes::PREFERENCE_DEFAULT;
        }
        int resourceId = rrow.Get_resource_id();

        // get matching user setting
        ACE_DB_SELECT(select, AceWidgetDevCapSetting, &AceDaoUtilities::m_databaseInterface);

        select->Where(And(Equals<AceWidgetDevCapSetting::resource_id>(resourceId),
                Equals<AceWidgetDevCapSetting::app_id>(handler)));

        std::list<int> values =
            select->GetValueList<AceWidgetDevCapSetting::access_value>();
        if (values.empty()) {
            return PreferenceTypes::PREFERENCE_DEFAULT;
        }
        return intToPreference(values.front());
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in getUserSetting");
    }
}

void AceDAOReadOnly::getRequestedDevCaps(
    WidgetHandle widgetHandle,
    RequestedDevCapsMap *permissions)
{
    if (NULL == permissions) {
        LogError("NULL pointer");
        return;
    }
    permissions->clear();
    Try {
        ACE_DB_SELECT(select, AceRequestedDevCaps,
                      &AceDaoUtilities::m_databaseInterface);
        select->Where(
            Equals<AceRequestedDevCaps::app_id>(widgetHandle));
        std::list<AceRequestedDevCaps::Row> list = select->GetRowList();

        FOREACH(i, list) {
            permissions->insert(std::make_pair(i->Get_dev_cap(),
                   i->Get_grant_smack() == 1));
        }
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getRequestedDevCaps");
    }
}

void AceDAOReadOnly::getAcceptedFeature(
    WidgetHandle widgetHandle,
    FeatureNameVector *fvector)
{
    if (NULL == fvector) {
        LogError("NULL pointer");
        return;
    }

    fvector->clear();
    Try {
        ACE_DB_SELECT(select, AceAcceptedFeature,
                      &AceDaoUtilities::m_databaseInterface);
        select->Where(
            Equals<AceAcceptedFeature::app_id>(widgetHandle));
        std::list<AceAcceptedFeature::Row> list = select->GetRowList();

        FOREACH(i, list) {
            fvector->push_back(i->Get_feature());
        }
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getRequestedDevCaps");
    }
}

AppTypes AceDAOReadOnly::getWidgetType(WidgetHandle handle)
{
    Try {
        ACE_DB_SELECT(select, WidgetInfo, &AceDaoUtilities::m_databaseInterface);
        select->Where(Equals<WidgetInfo::app_id>(handle));
        WidgetInfo::Select::RowList rows = select->GetRowList();
        DPL::OptionalInt res;
        if (!rows.empty()) {
            res = rows.front().Get_widget_type();
            AppTypes retType = (res.IsNull() ? AppTypes::Unknown : static_cast<AppTypes>(*res));
            return retType;
        } else {
            LogDebug("Can not find widget type");
            return AppTypes::Unknown;
        }
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getWidgetType");
    }
}

std::string AceDAOReadOnly::getVersion(WidgetHandle widgetHandle)
{
    Try
    {
        ACE_DB_SELECT(select, WidgetInfo, &AceDaoUtilities::m_databaseInterface);
        select->Where(Equals<WidgetInfo::app_id>(widgetHandle));
        WidgetInfo::Select::RowList rows = select->GetRowList();
        DPL::OptionalString res;
        if(!rows.empty()) {
            res = rows.front().Get_widget_version();
            return (res.IsNull() ? "" : DPL::ToUTF8String(*res));
        } else {
            LogDebug("Widget not installed");
            return "";
        }
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getVersion");
    }
}

std::string AceDAOReadOnly::getAuthorName(WidgetHandle widgetHandle)
{
    Try
    {
        ACE_DB_SELECT(select, WidgetInfo, &AceDaoUtilities::m_databaseInterface);
        select->Where(Equals<WidgetInfo::app_id>(widgetHandle));
        WidgetInfo::Select::RowList rows = select->GetRowList();
        DPL::OptionalString res;
        if(!rows.empty()) {
            res = rows.front().Get_author_name();
            return (res.IsNull() ? "" : DPL::ToUTF8String(*res));
        } else {
            LogDebug("Widget not installed");
            return "";
        }
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getAuthorName");
    }
}

std::string AceDAOReadOnly::getGUID(WidgetHandle widgetHandle)
{
    Try
    {
        ACE_DB_SELECT(select, WidgetInfo, &AceDaoUtilities::m_databaseInterface);
        select->Where(Equals<WidgetInfo::app_id>(widgetHandle));
        WidgetInfo::Select::RowList rows = select->GetRowList();
        DPL::OptionalString res;
        if(!rows.empty()) {
            res = rows.front().Get_widget_id();
            return (res.IsNull() ? "" : DPL::ToUTF8String(*res));
        } else {
            LogDebug("Widget not installed");
            return "";
        }
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getGUID");
    }
}

WidgetCertificateCNList AceDAOReadOnly::getKeyCommonNameList(
        WidgetHandle widgetHandle,
        WidgetCertificateData::Owner owner,
        WidgetCertificateData::Type type)
{
    Try {
        ACE_DB_SELECT(select, WidgetCertificateFingerprint, &AceDaoUtilities::m_databaseInterface);
        select->Where(And(And(
            Equals<WidgetCertificateFingerprint::app_id>(widgetHandle),
            Equals<WidgetCertificateFingerprint::owner>(owner)),
            Equals<WidgetCertificateFingerprint::type>(type)));
        WidgetCertificateFingerprint::Select::RowList rows = select->GetRowList();

        WidgetCertificateCNList out;
        FOREACH(it, rows)
        {
            DPL::Optional<DPL::String> cn = it->Get_common_name();
            out.push_back(cn.IsNull() ? "" : DPL::ToUTF8String(*cn));
        }
        return out;
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getKeyCommonNameList");
    }
}

FingerPrintList AceDAOReadOnly::getKeyFingerprints(
        WidgetHandle widgetHandle,
        WidgetCertificateData::Owner owner,
        WidgetCertificateData::Type type)
{
    Try
    {
        ACE_DB_SELECT(select, WidgetCertificateFingerprint, &AceDaoUtilities::m_databaseInterface);
        select->Where(And(And(
            Equals<WidgetCertificateFingerprint::app_id>(widgetHandle),
            Equals<WidgetCertificateFingerprint::owner>(owner)),
            Equals<WidgetCertificateFingerprint::type>(type)));
        WidgetCertificateFingerprint::Select::RowList rows = select->GetRowList();

        FingerPrintList keys;
        FOREACH(it, rows)
        {
            DPL::Optional<DPL::String> sha1 = it->Get_sha1_fingerprint();
            if (!sha1.IsNull())
                keys.push_back(DPL::ToUTF8String(*sha1));
            DPL::Optional<DPL::String> md5 = it->Get_md5_fingerprint();
            if (!md5.IsNull())
                keys.push_back(DPL::ToUTF8String(*md5));
        }
        return keys;
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getKeyFingerprints");
    }
}

std::string AceDAOReadOnly::getShareHref(WidgetHandle widgetHandle)
{
    Try
    {
        ACE_DB_SELECT(select, WidgetInfo, &AceDaoUtilities::m_databaseInterface);
        select->Where(Equals<WidgetInfo::app_id>(widgetHandle));
        WidgetInfo::Select::RowList rows = select->GetRowList();

        if(rows.empty())
            ThrowMsg(Exception::DatabaseError, "Cannot find widget. Handle: " << widgetHandle);

        DPL::Optional<DPL::String> value = rows.front().Get_share_href();
        std::string ret = "";
        if(!value.IsNull())
            ret = DPL::ToUTF8String(*value);
        return ret;
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to getShareHref");
    }
}

WidgetHandleList AceDAOReadOnly::getHandleList()
{
    LogDebug("Getting DbWidgetHandle List");
    Try
    {
        ACE_DB_SELECT(select, WidgetInfo, &AceDaoUtilities::m_databaseInterface);
        return select->GetValueList<WidgetInfo::app_id>();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to list of widget handles");
    }
}

bool AceDAOReadOnly::isWidgetInstalled(WidgetHandle handle)
{
    Try {
        ACE_DB_SELECT(select, WidgetInfo, &AceDaoUtilities::m_databaseInterface);
        select->Where(Equals<WidgetInfo::app_id>(handle));
        WidgetInfo::Select::RowList rows = select->GetRowList();
        return !rows.empty() ? true : false;
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in isWidgetInstalled");
    }
}

}
