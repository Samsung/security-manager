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
 * @file       AceDAO.cpp
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    0.1
 * @brief
 */

#include <ace-dao-rw/AceDAO.h>

#include <openssl/md5.h>
#include <dpl/foreach.h>
#include <dpl/string.h>
#include <dpl/log/log.h>
#include <dpl/db/orm.h>
#include <ace-dao-ro/AceDAOUtilities.h>
#include <ace-dao-ro/AceDAOConversions.h>
#include <ace-dao-ro/AceDatabase.h>

using namespace DPL::DB::ORM;
using namespace DPL::DB::ORM::ace;
using namespace AceDB::AceDaoUtilities;
using namespace AceDB::AceDaoConversions;

namespace {
char const * const EMPTY_SESSION = "";
} // namespace

namespace AceDB{

void AceDAO::setPromptDecision(
    WidgetHandle widgetHandle,
    int ruleId,
    const DPL::OptionalString &session,
    PromptDecision decision)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);

        ACE_DB_DELETE(del, AcePromptDecision, &AceDaoUtilities::m_databaseInterface);
        del->Where(
            And(
                Equals<AcePromptDecision::app_id>(widgetHandle),
                Equals<AcePromptDecision::rule_id>(ruleId)));
        del->Execute();

        AcePromptDecision::Row row;
        row.Set_rule_id(ruleId);
        row.Set_decision(promptDecisionToInt(decision));
        row.Set_app_id(widgetHandle);
        row.Set_session(session);
        ACE_DB_INSERT(insert, AcePromptDecision, &AceDaoUtilities::m_databaseInterface);
        insert->Values(row);
        insert->Execute();

        transaction.Commit();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to setUserSetting");
    }
}

void AceDAO::removePolicyResult(
        const BaseAttributeSet &attributes)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);

        auto attrHash =  convertToHash(attributes);

        ACE_DB_DELETE(del,
                      AcePolicyResult,
                      &AceDaoUtilities::m_databaseInterface);
        del->Where(Equals<AcePolicyResult::hash>(attrHash));
        del->Execute();
        transaction.Commit();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to removeVerdict");
    }
}

void AceDAO::clearAllSettings(void)
{
    clearWidgetDevCapSettings();
    clearDevCapSettings();
}

void AceDAO::setDevCapSetting(const std::string &resource,
                              PreferenceTypes preference)
{
    Try {
        ACE_DB_UPDATE(update, AceDevCap, &AceDaoUtilities::m_databaseInterface);
        AceDevCap::Row row;
        row.Set_general_setting(preferenceToInt(preference));
        update->Values(row);
        update->Where(
            Equals<AceDevCap::id_uri>(DPL::FromUTF8String(resource)));
        update->Execute();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to SetResourceSetting");
    }
}

void AceDAO::removeDevCapSetting(const std::string &resource)
{
    Try {
        ACE_DB_UPDATE(update, AceDevCap, &AceDaoUtilities::m_databaseInterface);
        AceDevCap::Row row;
        row.Set_general_setting(preferenceToInt(PreferenceTypes::PREFERENCE_DEFAULT));
        update->Values(row);
        update->Where(
            Equals<AceDevCap::id_uri>(DPL::FromUTF8String(resource)));
        update->Execute();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to removeResourceSetting");
    }
}


void AceDAO::setWidgetDevCapSetting(const std::string &resource,
                                    WidgetHandle handler,
                                    PreferenceTypes preference)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);
        // TODO JOIN
        AceDevCap::Row rrow;
        if (!getResourceByUri(resource, rrow)) {
            ThrowMsg(Exception::DatabaseError, "Resource not found");
        }

        ACE_DB_INSERT(insert,
                      AceWidgetDevCapSetting,
                      &AceDaoUtilities::m_databaseInterface);

        AceWidgetDevCapSetting::Row row;
        row.Set_app_id(handler);
        int rid = rrow.Get_resource_id();
        row.Set_resource_id(rid);
        row.Set_access_value(preferenceToInt(preference));
        insert->Values(row);
        insert->Execute();

        transaction.Commit();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to setUserSetting");
    }
}

void AceDAO::removeWidgetDevCapSetting(const std::string &resource,
                                       WidgetHandle handler)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);
        AceDevCap::Row rrow;
        if (!getResourceByUri(resource, rrow)) {
            ThrowMsg(Exception::DatabaseError, "resource not found");
        }

        ACE_DB_DELETE(del,
                      AceWidgetDevCapSetting,
                      &AceDaoUtilities::m_databaseInterface);

        Equals<AceWidgetDevCapSetting::app_id> e1(handler);
        Equals<AceWidgetDevCapSetting::resource_id> e2(rrow.Get_resource_id());
        del->Where(And(e1, e2));
        del->Execute();
        transaction.Commit();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to clearUserSettings");
    }
}


void AceDAO::setPolicyResult(const BaseAttributeSet &attributes,
                             const ExtendedPolicyResult &exResult)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);

        // TODO: this call is connected with logic.
        // It should be moved to PolicyEvaluator
        addAttributes(attributes);

        auto attrHash = convertToHash(attributes);

        ACE_DB_DELETE(del, AcePolicyResult, &AceDaoUtilities::m_databaseInterface)
        del->Where(Equals<AcePolicyResult::hash>(attrHash));
        del->Execute();

        ACE_DB_INSERT(insert, AcePolicyResult, &AceDaoUtilities::m_databaseInterface);
        AcePolicyResult::Row row;
        row.Set_decision(PolicyResult::serialize(exResult.policyResult));
        row.Set_hash(attrHash);
        row.Set_rule_id(exResult.ruleId);
        insert->Values(row);
        insert->Execute();

        transaction.Commit();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to addVerdict");
    }
}

void AceDAO::resetDatabase(void)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);
        ACE_DB_DELETE(del1, AcePolicyResult, &AceDaoUtilities::m_databaseInterface);
        del1->Execute();
        ACE_DB_DELETE(del2, AceWidgetDevCapSetting, &AceDaoUtilities::m_databaseInterface);
        del2->Execute();
        ACE_DB_DELETE(del3, AceDevCap, &AceDaoUtilities::m_databaseInterface);
        del3->Execute();
        ACE_DB_DELETE(del4, AceSubject, &AceDaoUtilities::m_databaseInterface);
        del4->Execute();
        ACE_DB_DELETE(del5, AceAttribute, &AceDaoUtilities::m_databaseInterface);
        del5->Execute();
        ACE_DB_DELETE(del6, AcePromptDecision, &AceDaoUtilities::m_databaseInterface);
        del6->Execute();

        transaction.Commit();

        // TODO there is no such query yet in ORM.
        //        GlobalConnection::DataCommandAutoPtr command =
        //                GlobalConnectionSingleton::Instance().PrepareDataCommand(
        //                        "VACUUM");
        //        command->Step();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to resetDatabase");
    }
}

void AceDAO::clearPolicyCache(void)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);
        ACE_DB_DELETE(del1, AcePolicyResult, &AceDaoUtilities::m_databaseInterface);
        del1->Execute();
        ACE_DB_DELETE(del2, AceAttribute, &AceDaoUtilities::m_databaseInterface);
        del2->Execute();
        ACE_DB_DELETE(del3, AcePromptDecision, &AceDaoUtilities::m_databaseInterface);
        del3->Execute();

        transaction.Commit();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to clearPolicyCache");
    }
}

void AceDAO::clearDevCapSettings()
{
    Try {
        ACE_DB_UPDATE(update, AceDevCap, &AceDaoUtilities::m_databaseInterface);
        AceDevCap::Row row;
        row.Set_general_setting(-1);
        update->Values(row);
        update->Execute();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to clearResourceSettings");
    }
}

void AceDAO::clearWidgetDevCapSettings()
{
    Try {
        ACE_DB_DELETE(del, AceWidgetDevCapSetting, &AceDaoUtilities::m_databaseInterface);
        del->Execute();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed to clearUserSettings");
    }
}

int AceDAO::addResource(const std::string &request)
{
    LogDebug("addResource: " << request);
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);
        AceDevCap::Row rrow;
        if (getResourceByUri(request, rrow)) {
            transaction.Commit();
            return rrow.Get_resource_id();
        }

        ACE_DB_INSERT(insert, AceDevCap, &AceDaoUtilities::m_databaseInterface);
        AceDevCap::Row row;
        row.Set_id_uri(DPL::FromUTF8String(request));
        row.Set_general_setting(-1);
        insert->Values(row);
        int id = insert->Execute();
        transaction.Commit();
        return id;
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in addResource");
    }
}

void AceDAO::addAttributes(const BaseAttributeSet &attributes)
{
    Try {
        BaseAttributeSet::const_iterator iter;

        for (iter = attributes.begin(); iter != attributes.end(); ++iter) {
            ACE_DB_SELECT(select, AceAttribute, &AceDaoUtilities::m_databaseInterface);
            select->Where(Equals<AceAttribute::name>(DPL::FromUTF8String(
                *(*iter)->getName())));
            std::list<AceAttribute::Row> rows = select->GetRowList();
            if (!rows.empty()) {
                continue;
            }

            ACE_DB_INSERT(insert, AceAttribute, &AceDaoUtilities::m_databaseInterface);
            AceAttribute::Row row;
            row.Set_name(DPL::FromUTF8String(*(*iter)->getName()));
            row.Set_type(attributeTypeToInt((*iter)->getType()));
            insert->Values(row);
            insert->Execute();
        }
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in addAttributes");
    }
}

void AceDAO::setWidgetType(WidgetHandle handle, AppTypes widgetType)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);

        ACE_DB_INSERT(insert, AceSubjectType, &AceDaoUtilities::m_databaseInterface);
        AceSubjectType::Row row;
        row.Set_app_id(handle);
        row.Set_app_type(appTypeToInt(widgetType));
        insert->Values(row);
        insert->Execute();
        transaction.Commit();
    }
    Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in setWidgetType");
    }
}

void AceDAO::setRequestedDevCaps(
    WidgetHandle widgetHandle,
    const RequestedDevCapsMap &permissions)
{
    Try {
        FOREACH(it, permissions) {
          ACE_DB_INSERT(insert, AceRequestedDevCaps,
                        &AceDaoUtilities::m_databaseInterface);
          AceRequestedDevCaps::Row row;
          row.Set_app_id(widgetHandle);
          row.Set_dev_cap(it->first);
          row.Set_grant_smack(it->second ? 1 : 0);
          insert->Values(row);
          insert->Execute();
        }
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in setStaticDevCapPermissions");
    }
}

void AceDAO::setAcceptedFeature(
    WidgetHandle widgetHandle,
    const FeatureNameVector &vector)
{
    Try {
        ScopedTransaction transaction(&AceDaoUtilities::m_databaseInterface);
        FOREACH(it, vector) {
            ACE_DB_INSERT(insert, AceAcceptedFeature,
                          &AceDaoUtilities::m_databaseInterface);
            AceAcceptedFeature::Row row;
            row.Set_app_id(widgetHandle);
            row.Set_feature(*it);
            insert->Values(row);
            insert->Execute();
        }
        transaction.Commit();
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in setAcceptedFeature");
    }
}

void AceDAO::removeAcceptedFeature(
    WidgetHandle widgetHandle)
{
    Try {
            ACE_DB_DELETE(del, AceAcceptedFeature,
                          &AceDaoUtilities::m_databaseInterface);
            del->Where(Equals<AceAcceptedFeature::app_id>(widgetHandle));
            del->Execute();
    } Catch(DPL::DB::SqlConnection::Exception::Base) {
        ReThrowMsg(Exception::DatabaseError, "Failed in removeAcceptedFeature");
    }
}

}
