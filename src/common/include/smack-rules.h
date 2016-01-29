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
#include <smack-exceptions.h>

struct smack_accesses;

namespace SecurityManager {

class SmackRules
{
public:
    SmackRules();
    virtual ~SmackRules();

    void add(const std::string &subject, const std::string &object,
            const std::string &permissions);
    void addModify(const std::string &subject, const std::string &object,
            const std::string &allowPermissions, const std::string &denyPermissions);
    void loadFromFile(const std::string &path);

    void addFromTemplate(
            const std::vector<std::string> &templateRules,
            const std::string &appId,
            const std::string &pkgId,
            const std::string &authorId,
            const std::string &zoneId);

    void addFromTemplateFile(
            const std::string &appId,
            const std::string &pkgId,
            const std::string &authorId,
            const std::string &zoneId);

    void apply() const;
    void clear() const;
    void saveToFile(const std::string &path) const;

    /**
     * Create cross dependencies for all applications in a package
     *
     * This is needed for all applications within a package to have
     * correct permissions to shared data.
     *
     * @param[in] pkgContents - a list of all applications inside this package
     * @param[in] zoneId - ID of zone which requested application install
     */
    void generatePackageCrossDeps(const std::vector<std::string> &pkgContents,
            const std::string &zoneId);

    /**
     * Create cross dependencies for all other 2.X applications
     *
     * @param[in] pkgId - installed package id to access it's shared dir
     * @param[in] other2XApps - list of 2.x apps to grant access
     * @param[in] zoneId - ID of zone which requested application install
     */
    void generateAllowOther2XApplicationDeps(const std::string pkgId,
            const std::vector<std::string> &other2XApps,
            const std::string &zoneId);

    /**
     * Install package-specific smack rules.
     *
     * Function creates smack rules using predefined template. Rules are applied
     * to the kernel and saved on persistent storage so they are loaded on system boot.
     *
     * @param[in] appId - application id that is beeing installed
     * @param[in] pkgId - package id that the application is in
     * @param[in] authorId - author id of application
     * @param[in] pkgContents - list of all applications in the package
     * @param[in] appsGranted - list of 2.x apps to grant access
     * @param[in] accessPackages - list of 2.x packages to be accessed
     */
    static void installApplicationRules(const std::string &appId,
            const std::string &pkgId,
            const std::string &authorId,
            const std::vector<std::string> &pkgContents,
            const std::vector<std::string> &appsGranted,
            const std::vector<std::string> &accessPackages);

    /**
     * Install package-specific smack rules plus add rules for specified external apps.
     *
     * Function creates smack rules using predefined template. Rules are applied
     * to the kernel and saved on persistent storage so they are loaded on system boot.
     *
     * @param[in] appId - application id that is beeing installed
     * @param[in] pkgId - package id that the application is in
     * @param[in] authorId - author id of application
     * @param[in] pkgContents - list of all applications in the package
     * @param[in] zoneId - ID of zone which requested application install
     * @param[in] appsGranted - list of 2.x apps granted access
     * @param[in] accessPackages - list of 2.x packages to be accessed
     */
    static void installApplicationRules(
            const std::string &appId,
            const std::string &pkgId,
            const std::string &authorId,
            const std::vector<std::string> &pkgContents,
            const std::vector<std::string> &appsGranted,
            const std::vector<std::string> &accessPackages,
            const std::string &zoneId);

    /**
     * Uninstall package-specific smack rules.
     *
     * Function loads package-specific smack rules, revokes them from the kernel
     * and removes them from the persistent storage.
     *
     * @param[in] pkgId - package identifier
     */
    static void uninstallPackageRules(const std::string &pkgId);

    /* FIXME: Remove this function if real pkgId instead of "User" label will be used
     * in generateAppLabel(). */
    static void addMissingRulesFix();

    /**
    * Uninstall application-specific smack rules.
    *
    * Function removes application specific rules from the kernel, and
    * removes them for persistent storage.
    *
    * @param[in] appId - application id
    * @param[in] pkgId - package id that the application belongs to
    * @param[in] appsInPkg - a list of other applications in the same package id that the application belongs to
    * @param[in] appsGranted - list of 2.x apps granted access
    * @param[in] zoneId - ID of zone which requested application uninstall
    */
    static void uninstallApplicationRules(const std::string &appId, const std::string &pkgId,
            std::vector<std::string> appsInPkg,
            const std::vector<std::string> &appsGranted,
            const std::string &zoneId);

    /**
     * Update package specific rules
     *
     * This function regenerates all package rules that
     * need to exist currently for all application in that
     * package
     *
     * @param[in] pkgId - id of the package to update
     * @param[in] pkgContents - list of all applications in the package
     * @param[in] appsGranted - list of 2.x apps granted access
     * @param[in] zoneId - ID of zone which requested application uninstall
     */
    static void updatePackageRules(const std::string &pkgId,
            const std::vector<std::string> &pkgContents,
            const std::vector<std::string> &appsGranted,
            const std::string &zoneId);

    /* Temporary fix for authors rules */
    static void fixAuthorRules(const std::string &authorId);

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
     */
    static void uninstallRules (const std::string &path);

    /**
     * Allow application to access other packages shared directory.
     *
     * @param[in] path - path to the file that contains the rules
     * @param[in] other2XPackages - list of 2.x packages to be accessed
     * @param[in] zoneId - ID of zone which requested application uninstall
     */
    static void generateAppToOtherPackagesDeps(const std::string appId,
            const std::vector<std::string> &other2XPackages,
            const std::string &zoneId);

    /**
     * Helper method: replace all occurrences of \ref needle in \ref haystack
     * with \ref replace.
     *
     * @param[in,out] haystack string to modify
     * @param needle string to find in \ref haystack
     * @param replace string to replace \ref needle with
     */
    static void strReplace(std::string &haystack, const std::string &needle,
            const std::string &replace);

    smack_accesses *m_handle;
};

} // namespace SecurityManager

#endif /* _SMACK_RULES_H_ */
