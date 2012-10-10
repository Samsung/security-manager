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
 * @file        ace_api_install.cpp
 * @author      Tomasz Swierczek (t.swierczek@samsung.com)
 * @version     1.0
 * @brief       This file contains implementation ACE installator API
 */

#include <string>
#include <utility>
#include <string.h>
#include <dpl/log/log.h>
#include <dpl/foreach.h>
#include <dpl/string.h>
#include <dpl/dbus/dbus_client.h>
#include <ace-dao-rw/AceDAO.h>
#include "ace_server_api.h"
#include "security_daemon_dbus_config.h"

#include "ace_api_install.h"

static DPL::DBus::Client *dbusClient = NULL;

// helper functions

static AceDB::AppTypes to_db_app_type(ace_widget_type_t widget_type)
{
    switch (widget_type) {
    case WAC20:
        return AceDB::AppTypes::WAC20;
    case Tizen:
        return AceDB::AppTypes::Tizen;
    default:
        return AceDB::AppTypes::Unknown;
    }
}

static ace_widget_type_t to_ace_widget_type(AceDB::AppTypes app_type)
{
    switch (app_type) {
    case AceDB::AppTypes::WAC20:
        return WAC20;
    case AceDB::AppTypes::Tizen:
        return Tizen;
    default:
        LogError("Invalid app type for widget");
        return WAC20;
    }
}

ace_return_t ace_install_initialize(void)
{
    if (NULL != dbusClient) {
        LogError("ace_api_install already initialized");
        return ACE_INTERNAL_ERROR;
    }
    AceDB::AceDAO::attachToThreadRW();
    Try {
        dbusClient = new DPL::DBus::Client(
                   WrtSecurity::SecurityDaemonConfig::OBJECT_PATH(),
                   WrtSecurity::SecurityDaemonConfig::SERVICE_NAME(),
                   WrtSecurity::AceServerApi::INTERFACE_NAME());
        std::string hello = "RPC test.";
        std::string response;
        dbusClient->call(WrtSecurity::AceServerApi::ECHO_METHOD(),
                          hello,
                          &response);
        LogInfo("Security daemon response from echo: " << response);
    } Catch (DPL::DBus::Client::Exception::DBusClientException) {
        LogError("Can't connect to daemon");
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_install_shutdown(void)
{
    if (NULL == dbusClient) {
        LogError("ace_api_install not initialized");
        return ACE_INTERNAL_ERROR;
    }
    delete dbusClient;
    dbusClient = NULL;
    AceDB::AceDAO::detachFromThread();
    return ACE_OK;
}

ace_return_t ace_update_policy(void)
{
    Try {
        dbusClient->call(WrtSecurity::AceServerApi::UPDATE_POLICY_METHOD());
    } Catch (DPL::DBus::Client::Exception::DBusClientException) {
        LogError("Problem with connection to daemon");
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_free_requested_dev_caps(ace_requested_dev_cap_list_t* caps)
{
    if (NULL == caps || NULL == caps->items) {
        LogError("Invalid arguments");
        return ACE_INVALID_ARGUMENTS;
    }
    unsigned int i;
    for (i = 0; i < caps->count; ++i) {
        delete [] caps->items[i].device_capability;
    }
    delete [] caps->items;
    return ACE_OK;
}

ace_return_t ace_get_requested_dev_caps(ace_widget_handle_t handle,
                                        ace_requested_dev_cap_list_t* caps)
{
    if (NULL == caps) {
        LogError("Invalid arguments");
        return ACE_INVALID_ARGUMENTS;
    }
    AceDB::RequestedDevCapsMap permissions;
    Try {
        AceDB::AceDAO::getRequestedDevCaps(
                handle, &permissions);
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    caps->items = new ace_requested_dev_cap_t[permissions.size()];
    caps->count = permissions.size();
    unsigned int i = 0;
    FOREACH (it, permissions) {
        std::string devCapRequested = DPL::ToUTF8String(it->first);
        caps->items[i].device_capability =
                new char[strlen(devCapRequested.c_str())+1];
        strcpy(caps->items[i].device_capability, devCapRequested.c_str());
        caps->items[i].smack_granted = it->second ? ACE_TRUE : ACE_FALSE;
        ++i;
    }
    return ACE_OK;
}

ace_return_t ace_set_requested_dev_caps(
        ace_widget_handle_t handle,
        const ace_requested_dev_cap_list_t* caps)
{
    if (NULL == caps) {
        LogError("Invalid arguments");
        return ACE_INVALID_ARGUMENTS;
    }
    AceDB::RequestedDevCapsMap db_permissions;
    unsigned int i;
    for (i = 0; i < caps->count; ++i) {
        std::string devCap = std::string(caps->items[i].device_capability);
        db_permissions.insert(std::make_pair(DPL::FromUTF8String(devCap),
                              caps->items[i].smack_granted == ACE_TRUE));
    }
    Try {
        AceDB::AceDAO::setRequestedDevCaps(
                handle, db_permissions);
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_set_accepted_feature(
        ace_widget_handle_t handle,
        const ace_feature_list_t *feature)
{
    if (NULL == feature) {
        LogError("Invalid argument");
        return ACE_INVALID_ARGUMENTS;
    }
    AceDB::FeatureNameVector fvector;
    ace_size_t i;
    for (i = 0; i < feature->count; ++i) {
        fvector.push_back(
            DPL::FromUTF8String(feature->items[i]));
    }
    Try {
        AceDB::AceDAO::setAcceptedFeature(handle, fvector);
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_rem_accepted_feature(
        ace_widget_handle_t handle)
{
    Try {
        AceDB::AceDAO::removeAcceptedFeature(handle);
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_register_widget(ace_widget_handle_t handle,
                                 struct widget_info *info,
                                 ace_certificate_data* cert_data[])
{
    LogDebug("enter");
    AceDB::WidgetRegisterInfo wri;
    wri.type = to_db_app_type(info->type);

    //TODO: type should be only in WidgetInfo database table
    ace_set_widget_type(handle, info->type);

    if (info->id)
        wri.widget_id = DPL::FromUTF8String(info->id);
    if (info->version)
        wri.version = DPL::FromUTF8String(info->version);
    if (info->author)
        wri.authorName = DPL::FromUTF8String(info->author);
    if (info->shareHerf)
        wri.shareHref = DPL::FromUTF8String(info->shareHerf);

    AceDB::WidgetCertificateDataList dataList;
    AceDB::WidgetCertificateData wcd;
    ace_certificate_data* cd;
    int i = 0;
    while (cert_data[i] != NULL)
    {
        cd = cert_data[i++]; //increment
        switch(cd->type) {
        case ROOT:
            wcd.type = AceDB::WidgetCertificateData::Type::ROOT;
            break;
        case ENDENTITY:
            wcd.type = AceDB::WidgetCertificateData::Type::ENDENTITY;
            break;
        }
        switch(cd->owner) {
        case AUTHOR:
            wcd.owner = AceDB::WidgetCertificateData::Owner::AUTHOR;
            break;
        case DISTRIBUTOR:
            wcd.owner = AceDB::WidgetCertificateData::Owner::DISTRIBUTOR;
            break;
        case UNKNOWN: default:
            wcd.owner = AceDB::WidgetCertificateData::Owner::UNKNOWN;
            break;
        }
        wcd.chainId = cd->chain_id;
        if (cd->md5_fp)
            wcd.strMD5Fingerprint = cd->md5_fp;
        if (cd->sha1_fp)
            wcd.strSHA1Fingerprint = cd->sha1_fp;
        if (cd->common_name)
            wcd.strCommonName = DPL::FromUTF8String(cd->common_name);
        dataList.push_back(wcd);
    }
    LogDebug("All data set. Inserting into database.");

    Try {
        AceDB::AceDAO::registerWidgetInfo((WidgetHandle)(handle), wri, dataList);
        LogDebug("AceDB entry done");
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_unregister_widget(ace_widget_handle_t handle)
{
    Try {
        AceDB::AceDAO::unregisterWidgetInfo((WidgetHandle)(handle));
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_is_widget_installed(ace_widget_handle_t handle, bool *installed)
{
    Try {
        *installed = AceDB::AceDAO::isWidgetInstalled((WidgetHandle)(handle));
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_set_widget_type(ace_widget_handle_t handle,
                                 ace_widget_type_t type)
{
    Try {
        AceDB::AceDAO::setWidgetType(
                handle, to_db_app_type(type));
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_get_widget_type(ace_widget_handle_t handle,
                                 ace_widget_type_t* type)
{
    if (NULL == type) {
        LogError("Invalid arguments");
        return ACE_INVALID_ARGUMENTS;
    }
    Try {
        AceDB::AppTypes db_type = AceDB::AceDAO::getWidgetType(handle);
        *type = to_ace_widget_type(db_type);
    } Catch(AceDB::AceDAOReadOnly::Exception::DatabaseError) {
        return ACE_INTERNAL_ERROR;
    }
    return ACE_OK;
}

ace_return_t ace_get_policy_result(const ace_resource_t resource,
                                   ace_widget_handle_t handle,
                                   ace_policy_result_t* result)
{
    if (NULL == result) {
        LogError("Invalid arguments");
        return ACE_INVALID_ARGUMENTS;
    }
    int serializedPolicyResult = 0;
    Try {
       std::string resource_str(resource);
       dbusClient->call(WrtSecurity::AceServerApi::CHECK_ACCESS_INSTALL_METHOD(),
                        handle,
                        resource_str,
                        &serializedPolicyResult);
   } Catch (DPL::DBus::Client::Exception::DBusClientException) {
       LogError("Can't connect to daemon");
       return ACE_INTERNAL_ERROR;
   }
   PolicyResult policyResult = PolicyResult::
           deserialize(serializedPolicyResult);
   OptionalPolicyEffect effect = policyResult.getEffect();
   if (effect.IsNull()) {
       *result = ACE_UNDEFINED;
   } else if (*effect == PolicyEffect::DENY) {
       *result = ACE_DENY;
   } else if (*effect == PolicyEffect::PERMIT) {
       *result = ACE_PERMIT;
   } else if (*effect == PolicyEffect::PROMPT_ONESHOT ||
              *effect == PolicyEffect::PROMPT_BLANKET ||
              *effect == PolicyEffect::PROMPT_SESSION){
       *result = ACE_PROMPT;
   } else {
       *result = ACE_UNDEFINED;
   }

   return ACE_OK;
}
