/*
 *  Copyright (c) 2014 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
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
 * @file        smack-rules.h
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @version     1.0
 * @brief       Header file of a class managing smack rules
 *
 */
#ifndef _SMACK_RULES_H_
#define _SMACK_RULES_H_

#include <vector>
#include <string>

struct smack_accesses;

namespace SecurityManager {

class SmackRules
{
public:
    SmackRules();
    virtual ~SmackRules();

    bool add(const std::string &subject, const std::string &object,
            const std::string &permissions);
    bool addModify(const std::string &subject, const std::string &object,
            const std::string &allowPermissions, const std::string &denyPermissions);
    bool loadFromFile(const std::string &path);
    bool addFromTemplate(const std::vector<std::string> &templateRules,
        const std::string &appId, const std::string &pkgId);
    bool addFromTemplateFile(const std::string &appId, const std::string &pkgId);

    bool apply() const;
    bool clear() const;
    bool saveToFile(const std::string &path) const;

    /**
     * Create cross dependencies for all applications in a package
     *
     * This is needed for all applications within a package to have
     * correct permissions to shared data.
     *
     * @param[in] pkgContents - a list of all applications inside this package
     * @return true on success, false on error
     */
    bool generatePackageCrossDeps(const std::vector<std::string> &pkgContents);
    /**
     * Install package-specific smack rules.
     *
     * Function creates smack rules using predefined template. Rules are applied
     * to the kernel and saved on persistent storage so they are loaded on system boot.
     *
     * @param[in] appId - application id that is beeing installed
     * @param[in] pkgId - package id that the application is in
     * @param[in] pkgContents - a list of all applications in the package
     * @return true on success, false on error
     */
    static bool installApplicationRules(const std::string &appId, const std::string &pkgId,
        const std::vector<std::string> &pkgContents);
    /**
     * Uninstall package-specific smack rules.
     *
     * Function loads package-specific smack rules, revokes them from the kernel
     * and removes them from the persistent storage.
     *
     * @param[in] pkgId - package identifier
     * @return true if smack rule file has been uninstalled or didn't exist
     *         false otherwise
     */
    static bool uninstallPackageRules(const std::string &pkgId);
    /* FIXME: Remove this function if real pkgId instead of "User" label will be used
     * in generateAppLabel(). */
    static bool addMissingRulesFix();
    /**
    * Uninstall application-specific smack rules.
    *
    * Function removes application specific rules from the kernel, and
    * removes them for persistent storage.
    *
    * @param[in] appId - application id
    * @param[in] pkgId - package id that the application belongs to
    * @param[in] appsInPkg - a list of other applications in the same package id that the application belongs to
    * @return true if smack rules have been removed false otherwise
    */
    static bool uninstallApplicationRules(const std::string &appId, const std::string &pkgId,
            std::vector<std::string> appsInPkg);
    /**
     * Update package specific rules
     *
     * This function regenerates all package rules that
     * need to exist currently for all application in that
     * package
     *
     * @param[in] pkgId - id of the package to update
     * @param[in] pkgContents - a list of all applications in the package
     * @return true in case of success false otherwise
     */
    static bool updatePackageRules(const std::string &pkgId, const std::vector<std::string> &pkgContents);
private:
    /**
     * Create a path for package rules
     *
     */
    static std::string getPackageRulesFilePath(const std::string &pkgId);
    /**
     * Create a path for application rules
     */
    static std::string getApplicationRulesFilePath(const std::string &appId);
    /**
     * Uninstall rules inside a specified file path
     *
     * This is a utility function that will clear all
     * rules in the file specified by path
     *
     * @param[in] path - path to the file that contains the rules
     * @return true in case of success false otherwise
     */
    static bool uninstallRules (const std::string &path);

    smack_accesses *m_handle;
};

} // namespace SecurityManager

#endif /* _SMACK_RULES_H_ */
