/*
 *  Copyright (c) 2017 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/**
 * @file        src/license-manager/agent/agent_logic.cpp
 * @author      Bartlomiej Grzelewski <b.grzelewski@samsung.com>
 * @brief       This is the place where verification should take place
 */
#include <fstream>
#include <sstream>
#include <string>
#include <memory>

#include <alog.h>

#include <agent_logic.h>
#include <app-runtime.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

namespace LicenseManager {

typedef std::unique_ptr<char, decltype(free)*> CString;
typedef std::unique_ptr<X509, decltype(X509_free)*> CertPtr;
typedef std::unique_ptr<X509_STORE, decltype(X509_STORE_free)*> StorePtr;
typedef std::unique_ptr<X509_STORE_CTX, decltype(X509_STORE_CTX_free)*> StoreCtxPtr;

CertPtr readCertificate(const char *path) {
    std::ifstream input(path);
    std::stringstream ss;
    ss << input.rdbuf();
    auto data = ss.str();
    auto ptr = reinterpret_cast<const unsigned char *>(data.data());
    auto size = static_cast<int>(data.size());
    X509 *cert = d2i_X509(nullptr, &ptr, size);
    if (cert)
        return CertPtr(cert, X509_free);

    FILE *file = NULL;
    file = fopen(path, "r");
    if (file) {
        cert = PEM_read_X509(file, NULL, NULL, NULL);
        fclose(file);
    }
    return CertPtr(cert, X509_free);
}

int verify(const std::string &smack, int uid, const std::string &privilege) {
    char *providerPkgId = nullptr, *providerAppId = nullptr;
    char *clientAppId = nullptr, *clientPkgId = nullptr;
    char *providerLicensePath = nullptr;
    char *clientLicensePath = nullptr;
    int status = -1; // error

    if (SECURITY_MANAGER_SUCCESS != security_manager_get_app_defined_privilege_provider(
            privilege.c_str(),
            uid,
            &providerPkgId,
            &providerAppId))
    {
        ALOGD("Error in security_manager_get_app_defined_privilege_provider");
        return -1;
    }
    CString pPI(providerPkgId, free);
    CString pAI(providerAppId, free);

    if (SECURITY_MANAGER_SUCCESS != security_manager_get_app_defined_privilege_license(
            privilege.c_str(),
            uid,
            &providerLicensePath))
    {
        ALOGD("Error in security_manager_get_app_defined_privilege_license");
        return -1;
    }
    CString pLP(providerLicensePath, free);

    if (SECURITY_MANAGER_SUCCESS != security_manager_identify_app_from_cynara_client(
            smack.c_str(),
            &clientPkgId,
            &clientAppId))
    {
        ALOGD("Error in security_manager_identify_app_from_cynara_client");
        return -1;
    }
    CString cAI(clientAppId, free);
    CString cPI(clientPkgId, free);

    if (SECURITY_MANAGER_SUCCESS != security_manager_get_client_privilege_license(
            privilege.c_str(),
            clientPkgId,
            clientAppId,
            uid,
            &clientLicensePath))
    {
        ALOGD("Error in security_manager_get_client_privilege_license");
        return -1;
    }
    CString cLP(clientLicensePath, free);

    auto providerCert = readCertificate(providerLicensePath);
    auto clientCert = readCertificate(clientLicensePath);

    if (!providerCert) {
        ALOGD("Error reading provider certificate");
        return -1;
    }

    if (!clientCert) {
        ALOGD("Error reading client certificates!");
        return -1;
    }

    StorePtr store(X509_STORE_new(), X509_STORE_free);
    StoreCtxPtr storeCtx(X509_STORE_CTX_new(), X509_STORE_CTX_free);

    if (1 != X509_STORE_add_cert(store.get(), providerCert.get())) {
        ALOGD("X509_STORE_add_cert failed");
    } else if (0 == X509_STORE_CTX_init(storeCtx.get(), store.get(), clientCert.get(), nullptr)) { // check this nullptr
        ALOGD("X509_STORE_CTX_init failed");
    } else {
        X509_VERIFY_PARAM_set_flags(storeCtx->param, X509_V_FLAG_X509_STRICT);
        status = X509_verify_cert(storeCtx.get()); // 1 == ok; 0 == fail; -1 == error
    }

    ALOGD("App: %s Uid: %d Privilege: %s", smack.c_str(), uid, privilege.c_str());
    ALOGD("Privilege: %s is Provided by: %s/%s", privilege.c_str(), providerAppId, providerPkgId);
    ALOGD("Certificate paths client: %s provider: %s", clientLicensePath, providerLicensePath);
    ALOGD("Verification status (1 means good, 0 means fail, -1 means error): %d", status);
    return status;
}

std::string AgentLogic::process(const std::string &data) {
    std::stringstream ss(data);
    std::string smack, privilege;
    int uid;
    ss >> smack >> uid >> privilege;

    int status = verify(smack, uid, privilege);
    status = (status == 1) ? 1 : 0;

    std::stringstream out;
    out << status;
    return out.str();
}

} // namespace LicenseManager

