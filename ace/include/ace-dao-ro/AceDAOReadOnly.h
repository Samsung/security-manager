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
 * @file       AceDAOReadOnly.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @author     Grzegorz Krawczyk (g.krawczyk@samsung.com)
 * @version    0.1
 * @brief
 */

#ifndef ACE_DAO_READ_ONLY_H_
#define ACE_DAO_READ_ONLY_H_

#include <map>

#include <openssl/md5.h>
#include <dpl/string.h>
#include <dpl/exception.h>
#include <ace-dao-ro/PreferenceTypes.h>
#include <ace-dao-ro/BaseAttribute.h>
#include <ace-dao-ro/BasePermission.h>
#include <ace-dao-ro/AppTypes.h>
#include <ace-dao-ro/IRequest.h>
#include <ace/PolicyEffect.h>
#include <ace/PolicyResult.h>
#include <ace/PromptDecision.h>
#include <ace-dao-ro/common_dao_types.h>

namespace AceDB {

typedef std::map<DPL::String, bool> RequestedDevCapsMap;
typedef DPL::String FeatureName;
typedef std::vector<FeatureName> FeatureNameVector;

class AceDAOReadOnly
{
  public:
    class Exception
    {
      public:
        DECLARE_EXCEPTION_TYPE(DPL::Exception, Base)
        DECLARE_EXCEPTION_TYPE(Base, DatabaseError)
    };

    AceDAOReadOnly() {}

    static void attachToThreadRO(void);
    static void attachToThreadRW(void);
    static void detachFromThread(void);

    // policy effect/decision
    static OptionalExtendedPolicyResult getPolicyResult(
            const BaseAttributeSet &attributes);

    static OptionalExtendedPolicyResult getPolicyResult(
        const DPL::String &attrHash);

    static OptionalCachedPromptDecision getPromptDecision(
            WidgetHandle widgetHandle,
            int ruleId);

    // resource settings
    static PreferenceTypes getDevCapSetting(const std::string &resource);
    static void getDevCapSettings(PreferenceTypesMap *preferences);

    // user settings
    static void getWidgetDevCapSettings(BasePermissionList *permissions);
    static PreferenceTypes getWidgetDevCapSetting(
            const std::string &resource,
            WidgetHandle handler);

    static void getAttributes(BaseAttributeSet *attributes);

    // Getter for device capabilities that are requested in widgets config.
    //
    // Additional boolean flag means whether widget will always get
    // (at launch) the SMACK permissions needed to use the device cap).
    //
    // 'permissions' is the map of device cap names and smack status for
    // given widget handle.
    static void getRequestedDevCaps(
        WidgetHandle widgetHandle,
        RequestedDevCapsMap *permissions);

    static void getAcceptedFeature(
        WidgetHandle widgetHandle,
        FeatureNameVector *featureVector);

    static WidgetHandleList getHandleList();

    static AppTypes getWidgetType(WidgetHandle handle);
    static std::string getVersion(WidgetHandle widgetHandle);
    static std::string getAuthorName(WidgetHandle widgetHandle);
    static std::string getGUID(WidgetHandle widgetHandle);

    static WidgetCertificateCNList getKeyCommonNameList(
            WidgetHandle widgetHandle,
            WidgetCertificateData::Owner owner,
            WidgetCertificateData::Type type);
    static FingerPrintList getKeyFingerprints(
            WidgetHandle widgetHandle,
            WidgetCertificateData::Owner owner,
            WidgetCertificateData::Type type);

    static std::string getShareHref(WidgetHandle widgetHandle);
    static bool isWidgetInstalled(WidgetHandle handle);

  protected:
    static int promptDecisionToInt(PromptDecision decision);
    static PromptDecision intToPromptDecision(int decision);
    static int appTypeToInt(AppTypes app_type);
    static AppTypes intToAppType(int app_type);
};

}

#endif
