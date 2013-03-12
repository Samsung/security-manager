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
 * This file contains classes that implement WRT_INTERFACE.h interfaces,
 * so that ACE could access  WRT specific and other information during
 * the decision making.
 *
 * @file    attribute_.cpp
 * @author  Jaroslaw Osmanski (j.osmanski@samsung.com)
 * @author  Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @author  Ming Jin(ming79.jin@samsung.com)
 * @version 1.0
 * @brief   Implementation file for attributes obtaining.
 */

#include <dpl/exception.h>
#include <sstream>
#include <algorithm>
#include <list>
#include <string>
#include <sstream>
#include <stdexcept>
#include <map>
#include <cstdlib>
#include <ace-dao-ro/AceDAOReadOnly.h>
#include <ace/WRT_INTERFACE.h>
#include <map>
#include <dpl/log/log.h>
#include <dpl/foreach.h>
#include <attribute_facade.h>
#include <ace/Request.h>
#include <simple_roaming_agent.h>

namespace // anonymous
{
typedef std::list<std::string> AttributeHandlerResponse;

typedef AttributeHandlerResponse (*AttributeHandler)(
    const WidgetExecutionPhase &phase,
    const WidgetHandle &widgetHandle);
typedef AttributeHandlerResponse (*ResourceAttributeHandler)(
    const WidgetExecutionPhase &phase,
    const WidgetHandle &widgetHandle,
    const Request &request);

AttributeHandlerResponse AttributeClassHandler(const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle & /*widgetHandle*/)
{
    AttributeHandlerResponse response;
    response.push_back("widget");
    return response;
}

AttributeHandlerResponse AttributeInstallUriHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    std::string value = AceDB::AceDAOReadOnly::getShareHref(widgetHandle);
    if(!value.empty())
        response.push_back(value);
    return response;
}

AttributeHandlerResponse AttributeVersionHandler(const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;

    std::string value = AceDB::AceDAOReadOnly::getVersion(widgetHandle);

    if (!value.empty()) {
        response.push_back(value);
    }

    return response;
}

AttributeHandlerResponse AttributeDistributorKeyCnHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyCommonNameList(widgetHandle,
        AceDB::WidgetCertificateData::DISTRIBUTOR, AceDB::WidgetCertificateData::ENDENTITY);
    return response;
}

AttributeHandlerResponse AttributeDistributorKeyFingerprintHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyFingerprints(widgetHandle,
        AceDB::WidgetCertificateData::DISTRIBUTOR, AceDB::WidgetCertificateData::ENDENTITY);
    return response;
}

AttributeHandlerResponse AttributeDistributorKeyRootCnHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyCommonNameList(widgetHandle,
        AceDB::WidgetCertificateData::DISTRIBUTOR, AceDB::WidgetCertificateData::ROOT);
    return response;
}

AttributeHandlerResponse AttributeDistributorKeyRootFingerprintHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyFingerprints(widgetHandle,
        AceDB::WidgetCertificateData::DISTRIBUTOR, AceDB::WidgetCertificateData::ROOT);
    return response;
}

AttributeHandlerResponse AttributeAuthorKeyCnHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyCommonNameList(widgetHandle,
        AceDB::WidgetCertificateData::AUTHOR, AceDB::WidgetCertificateData::ENDENTITY);
    return response;
}

AttributeHandlerResponse AttributeAuthorKeyFingerprintHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyFingerprints(widgetHandle,
        AceDB::WidgetCertificateData::AUTHOR, AceDB::WidgetCertificateData::ENDENTITY);
    return response;
}

AttributeHandlerResponse AttributeAuthorKeyRootCnHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyCommonNameList(widgetHandle,
        AceDB::WidgetCertificateData::AUTHOR, AceDB::WidgetCertificateData::ROOT);
    return response;
}

AttributeHandlerResponse AttributeAuthorKeyRootFingerprintHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;
    response = AceDB::AceDAOReadOnly::getKeyFingerprints(widgetHandle,
        AceDB::WidgetCertificateData::AUTHOR, AceDB::WidgetCertificateData::ROOT);
    return response;
}

AttributeHandlerResponse AttributeNetworkAccessUriHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle & /*widgetHandle*/)
{
    AttributeHandlerResponse response;
    return response;
}

AttributeHandlerResponse AttributeIdHandler(const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;

    std::string wGUID = AceDB::AceDAOReadOnly::getGUID(widgetHandle);

    if (!wGUID.empty()) {
        response.push_back(wGUID);
    }
    return response;
}

AttributeHandlerResponse AttributeAuthorNameHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle &widgetHandle)
{
    AttributeHandlerResponse response;

    std::string value = AceDB::AceDAOReadOnly::getAuthorName(widgetHandle);

    if (!value.empty()) {
        response.push_back(value);
    }

    return response;
}

AttributeHandlerResponse AttributeRoamingHandler(
        const WidgetExecutionPhase &phase,
        const WidgetHandle & /*widgetHandle*/)
{
    AttributeHandlerResponse response;

    if (WidgetExecutionPhase_WidgetInstall == phase) {
        // TODO undetermind value
        response.push_back(std::string(""));
    } else if (SimpleRoamingAgentSingleton::Instance().IsRoamingOn()) {
        response.push_back(std::string("true"));
    } else {
        response.push_back(std::string("false"));
    }

    return response;
}

AttributeHandlerResponse AttributeBearerTypeHandler(
        const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle & /*widgetHandle*/)
{
    AttributeHandlerResponse response;

    std::string bearerName = "undefined-bearer-name";

    if (bearerName.empty()) {
        LogWarning("Bearer-type is NOT SET or empty");
    } else {
        response.push_back(bearerName);
    }

    return response;
}

struct AttributeHandlerContext
{
    std::string name;
    WidgetExecutionPhase allowedPhaseMask;
    AttributeHandler handler;
};

// Private masks
const WidgetExecutionPhase WidgetExecutionPhase_All =
    static_cast<WidgetExecutionPhase>(
        WidgetExecutionPhase_WidgetInstall |
        WidgetExecutionPhase_WidgetInstantiate |
        WidgetExecutionPhase_WebkitBind |
        WidgetExecutionPhase_Invoke);
const WidgetExecutionPhase WidgetExecutionPhase_NoWidgetInstall =
    static_cast<WidgetExecutionPhase>(
        WidgetExecutionPhase_WidgetInstantiate |
        WidgetExecutionPhase_WebkitBind |
        WidgetExecutionPhase_Invoke);

#define ALL_PHASE(name, handler) \
    { # name, WidgetExecutionPhase_All, handler },

#define NO_INSTALL(name, handler) \
    { # name, WidgetExecutionPhase_NoWidgetInstall, handler },

AttributeHandlerContext HANDLED_ATTRIBUTES_LIST[] = {
    ALL_PHASE(Class, &AttributeClassHandler)
    ALL_PHASE(install-uri, &AttributeInstallUriHandler)
    ALL_PHASE(version, &AttributeVersionHandler)
    ALL_PHASE(distributor-key-cn, &AttributeDistributorKeyCnHandler)
    ALL_PHASE(distributor-key-fingerprint,
              &AttributeDistributorKeyFingerprintHandler)
    ALL_PHASE(distributor-key-root-cn,
              &AttributeDistributorKeyRootCnHandler)
    ALL_PHASE(distributor-key-root-fingerprint,
              &AttributeDistributorKeyRootFingerprintHandler)
    ALL_PHASE(author-key-cn, &AttributeAuthorKeyCnHandler)
    ALL_PHASE(author-key-fingerprint, &AttributeAuthorKeyFingerprintHandler)
    ALL_PHASE(author-key-root-cn, &AttributeAuthorKeyRootCnHandler)
    ALL_PHASE(author-key-root-fingerprint,
              &AttributeAuthorKeyRootFingerprintHandler)
    ALL_PHASE(network-access-uri, &AttributeNetworkAccessUriHandler)
    ALL_PHASE(id, &AttributeIdHandler)
//    ALL_PHASE(name, &AttributeNameHandler)
//    ALL_PHASE(widget-attr:name, &AttributeWidgetAttrNameHandler)
    ALL_PHASE(author-name, &AttributeAuthorNameHandler)
    /* Enviroment  attributes*/
    NO_INSTALL(roaming, &AttributeRoamingHandler)
    NO_INSTALL(bearer-type, &AttributeBearerTypeHandler)
};

#undef ALL_PHASE
#undef NO_INSTALL

const size_t HANDLED_ATTRIBUTES_LIST_COUNT =
    sizeof(HANDLED_ATTRIBUTES_LIST) / sizeof(HANDLED_ATTRIBUTES_LIST[0]);

template<class T>
class lambdaCollectionPusher
{
  public:
    std::list<T>& m_collection;
    lambdaCollectionPusher(std::list<T>& collection) : m_collection(collection)
    {
    }
    void operator()(const T& element) const
    {
        m_collection.push_back(element);
    }
};

AttributeHandlerResponse AttributeDeviceCapHandler(const WidgetExecutionPhase & /*phase*/,
        const WidgetHandle & /*widgetHandle*/,
        const Request &request)
{
    AttributeHandlerResponse response;

    Request::DeviceCapabilitySet capSet = request.getDeviceCapabilitySet();
    LogDebug("device caps set contains");
    FOREACH(dc, capSet)
    {
        LogDebug("-> " << *dc);
    }

    std::for_each(
        capSet.begin(),
        capSet.end(),
        lambdaCollectionPusher<std::string>(response));

    return response;
}

//class lambdaFeatureEquality :
//    public std::binary_function<FeatureHandle, int, bool>
//{
//  public:
//    bool operator()(const FeatureHandle& wFeature,
//            const int& resurceId) const
//    {
//        return wFeature == resurceId;
//    }
//};
//
//class lambdaPushFeatureName :
//    public std::binary_function<WidgetFeature, AttributeHandlerResponse, void>
//{
//    void operator()(const WidgetFeature& wFeature,
//            AttributeHandlerResponse& response) const
//    {
//        response.push_back(DPL::ToUTF8String(wFeature.name));
//    }
//};

AttributeHandlerResponse AttributeApiFeatureHandler(
        const WidgetExecutionPhase & /* phase */,
        const WidgetHandle & /* widgetHandle */,
        const Request & /* request */)
{
    LogDebug("WAC 2.0 does not support api-feature and resource-id in policy.");
    AttributeHandlerResponse response;
    return response;
}

AttributeHandlerResponse AttributeFeatureInstallUriHandler(
        const WidgetExecutionPhase & /* phase */,
        const WidgetHandle & /* widgetHandle */,
        const Request & /* request */)
{
    LogDebug("WAC 2.0 does not support feature-install-uri is policy!");
    AttributeHandlerResponse response;
    return response;
}

AttributeHandlerResponse AttributeFeatureFeatureKeyCnHandler(
        const WidgetExecutionPhase & /* phase */,
        const WidgetHandle & /* widgetHandle */,
        const Request & /* request */)
{
    LogDebug("WAC 2.0 does not support feature-key-cn is policy!");
    AttributeHandlerResponse response;
    return response;
}

AttributeHandlerResponse AttributeFeatureKeyRootCnHandler(
        const WidgetExecutionPhase & /* phase */,
        const WidgetHandle & /* widgetHandle */,
        const Request & /* request */)
{
    LogDebug("WAC 2.0 does not support feature-key-root-cn is policy!");
    AttributeHandlerResponse response;
    return response;
}

AttributeHandlerResponse AttributeFeatureKeyRootFingerprintHandler(
        const WidgetExecutionPhase & /* phase */,
        const WidgetHandle & /* widgetHandle */,
        const Request & /* request */)
{
    LogDebug("WAC 2.0 does not support"
        " feature-key-root-fingerprint is policy!");
    AttributeHandlerResponse response;
    return response;
}

struct ResourceAttributeHandlerContext
{
    std::string name;
    WidgetExecutionPhase allowedPhaseMask;
    ResourceAttributeHandler handler;
};

#define ALL_PHASE(name, handler) \
    { # name, WidgetExecutionPhase_All, handler },

ResourceAttributeHandlerContext HANDLED_RESOURCE_ATTRIBUTES_LIST[] = {
    ALL_PHASE(device-cap, &AttributeDeviceCapHandler)
    ALL_PHASE(api-feature, &AttributeApiFeatureHandler)
    // For compatiblity with older policies we tread resource-id
    // identically as api-feature
    ALL_PHASE(resource-id, &AttributeApiFeatureHandler)

    ALL_PHASE(feature-install-uri, &AttributeFeatureInstallUriHandler)
    ALL_PHASE(feature-key-cn, &AttributeFeatureFeatureKeyCnHandler)
    ALL_PHASE(feature-key-root-cn, &AttributeFeatureKeyRootCnHandler)
    ALL_PHASE(feature-key-root-fingerprint,
              &AttributeFeatureKeyRootFingerprintHandler)
};

#undef ALL_PHASE

const size_t HANDLED_RESOURCE_ATTRIBUTES_LIST_COUNT =
    sizeof(HANDLED_RESOURCE_ATTRIBUTES_LIST) /
    sizeof(HANDLED_RESOURCE_ATTRIBUTES_LIST[0]);
} // namespace anonymous

/*
 * class WebRuntimeImpl
 */
int WebRuntimeImpl::getAttributesValuesLoop(const Request &request,
        std::list<ATTRIBUTE>* attributes,
        WidgetExecutionPhase executionPhase)
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        WidgetHandle widgetHandle = request.getWidgetHandle();

        FOREACH(itr, *attributes)
        {
            // Get attribute name
            std::string attribute = *itr->first;

            // Search for attribute handler
            bool attributeFound = false;

            for (size_t i = 0; i < HANDLED_ATTRIBUTES_LIST_COUNT; ++i) {
                if (HANDLED_ATTRIBUTES_LIST[i].name == attribute) {
                    // Check if execution phase is valid
                    if ((executionPhase &
                         HANDLED_ATTRIBUTES_LIST[i].allowedPhaseMask) == 0) {
                        // Attribute found, but execution state
                        // forbids to execute handler
                        LogWarning(
                            "Request for attribute: '" <<
                            attribute << "' which is supported " <<
                            "but forbidden at widget execution phase: "
                            <<
                            executionPhase);
                    } else {
                        // Execution phase allows handler
                        AttributeHandlerResponse attributeResponse =
                            (*HANDLED_ATTRIBUTES_LIST[i].handler)(
                                executionPhase,
                                widgetHandle);
                        std::copy(attributeResponse.begin(),
                                  attributeResponse.end(),
                                  std::back_inserter(*itr->second));
                    }

                    attributeFound = true;
                    break;
                }
            }

            if (!attributeFound) {
                LogWarning("Request for attribute: '" <<
                           attribute << "' which is not supported");
            }
        }

        return 0;
    }
    UNHANDLED_EXCEPTION_HANDLER_END
}

int WebRuntimeImpl::getAttributesValues(const Request &request,
        std::list<ATTRIBUTE>* attributes)
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        // Get current execution state
        WidgetExecutionPhase executionPhase =
            request.getExecutionPhase();

        return getAttributesValuesLoop(request, attributes, executionPhase);
    }
    UNHANDLED_EXCEPTION_HANDLER_END
}

std::string WebRuntimeImpl::getSessionId(const Request & /* request */)
{
    std::string result;
    LogError("Not implemented!");
    return result;
}

WebRuntimeImpl::WebRuntimeImpl()
{
}

/*
 * class ResourceInformationImpl
 */

int ResourceInformationImpl::getAttributesValuesLoop(const Request &request,
        std::list<ATTRIBUTE>* attributes,
        WidgetExecutionPhase executionPhase)
{
    // Currently, we assume widgets have internal representation of integer IDs
    WidgetHandle widgetHandle = request.getWidgetHandle();
    //TODO add resource id string analyzys
    FOREACH(itr, *attributes)
    {
        // Get attribute name
        std::string attribute = *itr->first;
        LogDebug("getting attribute value for: " << attribute);
        FOREACH(aaa, *itr->second)
        {
            LogDebug("its value is: " << *aaa);
        }

        // Search for attribute handler
        bool attributeFound = false;

        for (size_t i = 0; i < HANDLED_RESOURCE_ATTRIBUTES_LIST_COUNT; ++i) {
            if (HANDLED_RESOURCE_ATTRIBUTES_LIST[i].name == attribute) {
                // Check if execution phase is valid
                if ((executionPhase &
                     HANDLED_RESOURCE_ATTRIBUTES_LIST[i].allowedPhaseMask) ==
                    0) {
                    // Attribute found, but execution state
                    // forbids to execute handler
                    LogDebug(
                        "Request for attribute: '" <<
                        attribute <<
                        "' which is supported but forbidden " <<
                        "at widget execution phase: " << executionPhase);
                    itr->second = NULL;
                } else {
                    // Execution phase allows handler
                    AttributeHandlerResponse attributeResponse =
                        (*HANDLED_RESOURCE_ATTRIBUTES_LIST[i].handler)(
                            executionPhase,
                            widgetHandle,
                            request);
                    std::copy(attributeResponse.begin(),
                              attributeResponse.end(),
                              std::back_inserter(*itr->second));

                    std::ostringstream attributeResponseFull;

                    for (AttributeHandlerResponse::const_iterator
                         it = attributeResponse.begin();
                         it != attributeResponse.end(); ++it) {
                        attributeResponseFull <<
                        (it == attributeResponse.begin() ? "" : ", ") <<
                        *it;
                    }

                    LogDebug("Attribute(" << attribute << ") = " <<
                             attributeResponseFull.str());
                }

                attributeFound = true;
                break;
            }
        }

        if (!attributeFound) {
            LogWarning("Request for attribute: '" << attribute <<
                       "' which is not supported");
        }
    }
    return 0;
}

int ResourceInformationImpl::getAttributesValues(const Request &request,
        std::list<ATTRIBUTE>* attributes)
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        // Get current execution state
        WidgetExecutionPhase executionPhase =
            request.getExecutionPhase();
        return getAttributesValuesLoop(request, attributes, executionPhase);
    }
    UNHANDLED_EXCEPTION_HANDLER_END
}

ResourceInformationImpl::ResourceInformationImpl()
{
}

/*
 * class OperationSystemImpl
 */

int OperationSystemImpl::getAttributesValues(const Request &request,
        std::list<ATTRIBUTE>* attributes)
{
    UNHANDLED_EXCEPTION_HANDLER_BEGIN
    {
        //FIXME:
        //GetExecution name without widget name
        WidgetExecutionPhase executionPhase =
            request.getExecutionPhase();

        FOREACH(itr, *attributes)
        {
            // Get attribute name
            std::string attribute = *itr->first;

            // Search for attribute handler
            bool attributeFound = false;

            for (size_t i = 0; i < HANDLED_ATTRIBUTES_LIST_COUNT; ++i) {
                if (HANDLED_ATTRIBUTES_LIST[i].name == attribute) {
                    // Check if execution phase is valid
                    if ((executionPhase &
                         HANDLED_ATTRIBUTES_LIST[i].allowedPhaseMask) == 0) {
                        // Attribute found, but execution state forbids
                        // to execute handler
                        LogDebug("Request for attribute: '" << attribute <<
                                 "' which is supported but forbidden at " <<
                                 "widget execution phase: " << executionPhase);
                        itr->second = NULL;
                    } else {
                        // Execution phase allows handler
                        AttributeHandlerResponse attributeResponse =
                            (*HANDLED_ATTRIBUTES_LIST[i].handler)(
                                executionPhase,
                                0);
                        std::copy(attributeResponse.begin(),
                                  attributeResponse.end(),
                                  std::back_inserter(*itr->second));

                        std::ostringstream attributeResponseFull;

                        typedef AttributeHandlerResponse::const_iterator Iter;
                        FOREACH(it, attributeResponse)
                        {
                            attributeResponseFull <<
                            (it == attributeResponse.begin()
                             ? "" : ", ") << *it;
                        }

                        LogDebug("Attribute(" << attribute <<
                                 ") = " << attributeResponseFull.str());
                    }

                    attributeFound = true;
                    break;
                }
            }

            if (!attributeFound) {
                LogWarning("Request for attribute: '" << attribute <<
                           "' which is not supported");
            }
        }

        return 0;
    }
    UNHANDLED_EXCEPTION_HANDLER_END
}

OperationSystemImpl::OperationSystemImpl()
{
}

/*
 * end of class OperationSystemImpl
 */

int FunctionParamImpl::getAttributesValues(const Request & /*request*/,
        std::list<ATTRIBUTE> *attributes)
{
    FOREACH(iter, *attributes)
    {
        std::string attributeName = *(iter->first);

        ParamMap::const_iterator i;
        std::pair<ParamMap::const_iterator, ParamMap::const_iterator> jj =
            paramMap.equal_range(attributeName);

        for (i = jj.first; i != jj.second; ++i) {
            iter->second->push_back(i->second);
            LogDebug("Attribute: " << attributeName << " Value: " <<
                     i->second);
        }
    }
    return 0;
}
