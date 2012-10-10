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
 * @file       AceDAO.h
 * @author     Krzysztof Jackiewicz (k.jackiewicz@samsung.com)
 * @version    0.1
 * @brief
 */

#ifndef ACEDAO_H_
#define ACEDAO_H_

#include <list>
#include <map>
#include <string>

#include <dpl/optional_typedefs.h>
#include <dpl/string.h>
#include <ace-dao-ro/AceDAOReadOnly.h>
#include <ace-dao-ro/ValidityTypes.h>
#include <ace-dao-ro/AppTypes.h>

namespace AceDB {
/*
 *
 */
class AceDAO : public AceDAOReadOnly
{
  public:

    AceDAO() {}

    // Policy Decisions
    static void setPolicyResult(
            const BaseAttributeSet &attributes,
            const ExtendedPolicyResult &policyResult);

    static void removePolicyResult(
            const BaseAttributeSet &attributes);

    // PromptDecision
    static void setPromptDecision(
            WidgetHandle widgetHandle,
            int ruleId,
            const DPL::OptionalString &session,
            PromptDecision decision);

    static void clearPromptDecisions(void);

    // reseting database
    static void clearWidgetDevCapSettings(void);
    static void clearDevCapSettings(void);
    static void clearAllSettings(void);
    static void resetDatabase(void);
    // clears all databse information relevant to policy cache
    static void clearPolicyCache(void);

    // resource settings
    static void setDevCapSetting(const std::string &resource,
            PreferenceTypes preference);
    static void removeDevCapSetting(const std::string &resource);

    // user settings
    static void setWidgetDevCapSetting(
            const std::string &resource,
            WidgetHandle handler,
            PreferenceTypes);
    static void removeWidgetDevCapSetting(
            const std::string &resource,
            WidgetHandle handler);

    // resource and subject management
    static int addResource(const std::string &request);

    // utilities
    static void addAttributes(const BaseAttributeSet &attributes);

    // setting widget type
    static void setWidgetType(WidgetHandle handle, AppTypes widgetType);

    // Setter for device capabilities that are requested in widgets config.
    //
    // Additional boolean flag means whether widget will always get
    // (at launch) the SMACK permissions needed to use the device cap).
    //
    // 'permissions' is the map of device cap names and smack status for
    // given widget handle.
    static void setRequestedDevCaps(
        WidgetHandle widgetHandle,
        const RequestedDevCapsMap &permissions);

    static void setAcceptedFeature(
        WidgetHandle widgetHandle,
        const FeatureNameVector &vector);

    static void removeAcceptedFeature(WidgetHandle widgetHandle);

    static void registerWidgetInfo(WidgetHandle handle,
                                   const WidgetRegisterInfo& info,
                                   const WidgetCertificateDataList& dataList);
    static void unregisterWidgetInfo(WidgetHandle handle);
    static bool isWidgetInstalled(WidgetHandle handle);

} __attribute__ ((deprecated));
}
#endif /* ACEDAO_H_ */
