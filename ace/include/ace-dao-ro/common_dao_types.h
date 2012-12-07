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
 * @file    common_dao_types.h
 * @author  Bartlomiej Grzelewski (b.grzelewski@samsung.com)
 * @version 1.1
 * @brief   This file contains the declaration of common data types for ace database.
 */
#ifndef ACE_SRC_CONFIGURATION_COMMON_DAO_TYPES_H_
#define ACE_SRC_CONFIGURATION_COMMON_DAO_TYPES_H_

#include <list>
#include <dpl/optional_typedefs.h>
#include <dpl/string.h>
#include "AppTypes.h"

typedef int WidgetHandle;
typedef std::list<WidgetHandle> WidgetHandleList;

namespace AceDB {

enum {
    INVALID_PLUGIN_HANDLE = -1
};
typedef int DbPluginHandle;

enum CertificateSource {
    SIGNATURE_DISTRIBUTOR = 0,
    SIGNATURE_AUTHOR = 1
};

struct WidgetRegisterInfo {
    AppTypes type;
    DPL::OptionalString widget_id;
    DPL::OptionalString authorName;
    DPL::OptionalString version;
    DPL::OptionalString shareHref;
};

typedef std::list <std::string> WidgetCertificateCNList;

struct WidgetCertificateData {
    enum Owner { AUTHOR, DISTRIBUTOR, UNKNOWN };
    enum Type { ROOT, ENDENTITY };

    Owner owner;
    Type type;

    int chainId;
    std::string strMD5Fingerprint;
    std::string strSHA1Fingerprint;
    DPL::String strCommonName;

    bool operator== (const WidgetCertificateData& certData) const {
        return certData.chainId == chainId &&
           certData.owner == owner &&
           certData.strCommonName == strCommonName &&
           certData.strMD5Fingerprint == strMD5Fingerprint &&
           certData.strSHA1Fingerprint == strSHA1Fingerprint;
    }
};
typedef std::list<WidgetCertificateData> WidgetCertificateDataList;

typedef std::list<std::string> FingerPrintList;

typedef std::list<std::string> CertificateChainList;
class IWacSecurity {
  public:
    virtual ~IWacSecurity() {}
    virtual const WidgetCertificateDataList& getCertificateList() const = 0;
    virtual bool isRecognized() const = 0;
    virtual bool isDistributorSigned() const = 0;
    virtual bool isWacSigned() const = 0;
    virtual void getCertificateChainList(CertificateChainList& list) const = 0;
};

} //namespace AceDB

#endif /* ACE_SRC_CONFIGURATION_COMMON_DAO_TYPES_H_ */
