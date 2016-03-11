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
 * @file        smack-rules.cpp
 * @author      Jacek Bukarewicz <j.bukarewicz@samsung.com>
 * @version     1.0
 * @brief       Implementation of a class managing smack rules
 *
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <fcntl.h>
#include <fstream>
#include <cstring>
#include <sstream>
#include <memory>

#include <dpl/log/log.h>
#include <tzplatform_config.h>

#include "smack-labels.h"
#include "smack-rules.h"

namespace SecurityManager {

const char *const SMACK_APP_LABEL_TEMPLATE     = "~APP~";
const char *const SMACK_PKG_LABEL_TEMPLATE     = "~PKG~";
const char *const SMACK_AUTHOR_LABEL_TEMPLATE  = "~AUTHOR~";
const char *const APP_RULES_TEMPLATE_FILE_PATH = tzplatform_mkpath4(TZ_SYS_RO_SHARE, "security-manager", "policy", "app-rules-template.smack");
const char *const PKG_RULES_TEMPLATE_FILE_PATH = tzplatform_mkpath4(TZ_SYS_RO_SHARE, "security-manager", "policy", "pkg-rules-template.smack");
const char *const AUTHOR_RULES_TEMPLATE_FILE_PATH =
    tzplatform_mkpath4(TZ_SYS_RO_SHARE, "security-manager", "policy", "author-rules-template.smack");
const char *const SMACK_APP_IN_PACKAGE_PERMS   = "rwxat";
const char *const SMACK_APP_CROSS_PKG_PERMS    = "rx";
const char *const SMACK_APP_PATH_OWNER_PERMS = "rwxat";
const char *const SMACK_APP_PATH_TARGET_PERMS = "rxl";
const char *const SMACK_APP_DIR_TARGET_PERMS = "x";
const char *const SMACK_USER = "User";
const char *const SMACK_SYSTEM = "System";
const char *const SMACK_APP_PATH_SYSTEM_PERMS = "rwxat";
const char *const SMACK_APP_PATH_USER_PERMS = "rwxat";

SmackRules::SmackRules()
{
    if (smack_accesses_new(&m_handle) < 0) {
        LogError("Failed to create smack_accesses handle");
        throw std::bad_alloc();
    }
}

SmackRules::~SmackRules() {
    smack_accesses_free(m_handle);
}

void SmackRules::add(const std::string &subject, const std::string &object,
        const std::string &permissions)
{
    if (smack_accesses_add(m_handle, subject.c_str(), object.c_str(), permissions.c_str()))
        ThrowMsg(SmackException::LibsmackError, "smack_accesses_add");
}

void SmackRules::addModify(const std::string &subject, const std::string &object,
        const std::string &allowPermissions, const std::string &denyPermissions)
{
    if (smack_accesses_add_modify(m_handle, subject.c_str(), object.c_str(), allowPermissions.c_str(), denyPermissions.c_str()))
        ThrowMsg(SmackException::LibsmackError, "smack_accesses_add_modify");
}

void SmackRules::clear() const
{
    if (smack_accesses_clear(m_handle))
        ThrowMsg(SmackException::LibsmackError, "smack_accesses_clear");
}

void SmackRules::apply() const
{
    if (smack_accesses_apply(m_handle))
        ThrowMsg(SmackException::LibsmackError, "smack_accesses_apply");

}

void SmackRules::loadFromFile(const std::string &path)
{
    int fd;

    fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY));
    if (fd == -1) {
        LogError("Failed to open file: " << path);
        ThrowMsg(SmackException::FileError, "Failed to open file: " << path);
    }

    if (smack_accesses_add_from_file(m_handle, fd)) {
        LogError("Failed to load smack rules from file: " << path);
        ThrowMsg(SmackException::LibsmackError, "Failed to load smack rules from file: " << path);
    }

    if (close(fd) == -1) {
        // don't change the return code, the descriptor should be closed despite the error.
        LogWarning("Error while closing the file: " << path << ", error: " << strerror(errno));
    }
}

void SmackRules::saveToFile(const std::string &path, bool truncFile) const
{
    int fd;
    int flags = O_CREAT | O_WRONLY | (truncFile ? O_TRUNC : O_APPEND);

    fd = TEMP_FAILURE_RETRY(open(path.c_str(), flags, 0644));
    if (fd == -1) {
        LogError("Failed to create file: " << path);
        ThrowMsg(SmackException::FileError, "Failed to create file: " << path);
    }

    if (smack_accesses_save(m_handle, fd)) {
        LogError("Failed to save rules to file: " << path);
        unlink(path.c_str());
        ThrowMsg(SmackException::LibsmackError, "Failed to save rules to file: " << path);
    }

    if (close(fd) == -1) {
        if (errno == EIO) {
            LogError("I/O Error occured while closing the file: " << path << ", error: " << strerror(errno));
            unlink(path.c_str());
            ThrowMsg(SmackException::FileError, "I/O Error occured while closing the file: " << path << ", error: " << strerror(errno));
        } else {
            // non critical error
            // don't change the return code, the descriptor should be closed despite the error.
            LogWarning("Error while closing the file: " << path << ", error: " << strerror(errno));
        }
    }
}

void SmackRules::addFromTemplateFile(
        const std::string &templatePath,
        const std::string &appName,
        const std::string &pkgName,
        const int authorId)
{
    RuleVector templateRules;
    std::string line;
    std::ifstream templateRulesFile(templatePath);

    if (!templateRulesFile.is_open()) {
        LogError("Cannot open rules template file: " << templatePath);
        ThrowMsg(SmackException::FileError, "Cannot open rules template file: " << templatePath);
    }

    while (std::getline(templateRulesFile, line)) {
        templateRules.push_back(line);
    }

    if (templateRulesFile.bad()) {
        LogError("Error reading template file: " << templatePath);
        ThrowMsg(SmackException::FileError, "Error reading template file: " << templatePath);
    }

    addFromTemplate(templateRules, appName, pkgName, authorId);
}

void SmackRules::addFromTemplate(
        const RuleVector &templateRules,
        const std::string &appName,
        const std::string &pkgName,
        const int authorId)
{
    std::string appLabel;
    std::string pkgLabel;
    std::string authorLabel;

    if (!appName.empty())
        appLabel = SmackLabels::generateAppLabel(appName);

    if (!pkgName.empty())
        pkgLabel = SmackLabels::generatePkgLabel(pkgName);

    if (authorId >= 0)
        authorLabel = SmackLabels::generateAuthorLabel(authorId);

    for (auto rule : templateRules) {
        if (rule.empty())
            continue;

        std::stringstream stream(rule);
        std::string subject, object, permissions;
        stream >> subject >> object >> permissions;

        if (stream.fail() || !stream.eof()) {
            LogError("Invalid rule template: " << rule);
            ThrowMsg(SmackException::FileError, "Invalid rule template: " << rule);
        }

        strReplace(subject, SMACK_APP_LABEL_TEMPLATE, appLabel);
        strReplace(subject, SMACK_PKG_LABEL_TEMPLATE, pkgLabel);
        strReplace(object,  SMACK_APP_LABEL_TEMPLATE, appLabel);
        strReplace(object,  SMACK_PKG_LABEL_TEMPLATE, pkgLabel);
        strReplace(object,  SMACK_AUTHOR_LABEL_TEMPLATE, authorLabel);

        if (subject.empty() || object.empty())
            continue;

        add(subject, object, permissions);
    }
}

void SmackRules::generatePackageCrossDeps(const std::vector<std::string> &pkgContents)
{
    LogDebug ("Generating cross-package rules");

    std::string subjectLabel, objectLabel;
    std::string appsInPackagePerms = SMACK_APP_IN_PACKAGE_PERMS;

    for (const auto &subject : pkgContents) {
        for (const auto &object : pkgContents) {
            if (object == subject)
                continue;

            subjectLabel = SmackLabels::generateAppLabel(subject);
            objectLabel = SmackLabels::generateAppLabel(object);
            LogDebug ("Trying to add rule subject: " << subjectLabel << " object: " << objectLabel << " perms: " << appsInPackagePerms);
            add(subjectLabel, objectLabel, appsInPackagePerms);
        }
    }
}

void SmackRules::generateAppToOtherPackagesDeps(
        const std::string appName,
        const std::vector<std::string> &other2XPackages)
{
    // reverse: allow installed app to access others' contents
    // for every 2.X package
    for (const auto &object : other2XPackages) {
        std::string otherObjectLabel = SmackLabels::generatePkgLabelOwnerRWothersRO(object);

        SmackRules packageRules;
        std::string accessPackageRulesPath = getPackageRulesFilePath(object);
        packageRules.loadFromFile(accessPackageRulesPath);

        std::string subjectLabel = SmackLabels::generateAppLabel(appName);
        LogDebug("Addding cross app rule for newly installed subject " << subjectLabel << " to already installed 2.x package object: " << otherObjectLabel << " perms: " << SMACK_APP_CROSS_PKG_PERMS);
        packageRules.add(subjectLabel, otherObjectLabel, SMACK_APP_CROSS_PKG_PERMS);
        packageRules.saveToFile(accessPackageRulesPath);
        if (smack_smackfs_path() != NULL)
            packageRules.apply();
    }
}

/**
 * this below works in N^2 and should be replaced by an alternative mechanism
 */
void SmackRules::generateAllowOther2XApplicationDeps(
        const std::string pkgName,
        const std::vector<std::string> &other2XApps)
{
    LogDebug("Generating cross-package rules");

    std::string objectLabel = SmackLabels::generatePkgLabelOwnerRWothersRO(pkgName);
    std::string appsInPackagePerms = SMACK_APP_IN_PACKAGE_PERMS;

    // allow other app to access installed package contents
    for (const auto &subject : other2XApps) {
        std::string subjectLabel = SmackLabels::generateAppLabel(subject);

        LogDebug("Addding cross 2.x app rule subject: " << subjectLabel << " to newly installed object: "
            << objectLabel << " perms: " << SMACK_APP_CROSS_PKG_PERMS);
        add(subjectLabel, objectLabel, SMACK_APP_CROSS_PKG_PERMS);
    }
}

std::string SmackRules::getPackageRulesFilePath(const std::string &pkgName)
{
    std::string path(tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d", ("pkg_" + pkgName).c_str()));
    return path;
}

std::string SmackRules::getApplicationRulesFilePath(const std::string &appName)
{
    std::string path(tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d", ("app_" +  appName).c_str()));
    return path;
}

std::string SmackRules::getAuthorRulesFilePath(const int authorId)
{
    std::string authorIdStr = std::to_string(authorId);
    return tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d", ("author_" + authorIdStr).c_str());
}

void SmackRules::useTemplate(
        const std::string &templatePath,
        const std::string &outputPath,
        const std::string &appName,
        const std::string &pkgName,
        const int authorId)
{
    SmackRules smackRules;
    smackRules.addFromTemplateFile(templatePath, appName, pkgName, authorId);

    if (smack_smackfs_path() != NULL)
        smackRules.apply();

    smackRules.saveToFile(outputPath);
}

void SmackRules::installApplicationRules(
        const std::string &appName,
        const std::string &pkgName,
        const int authorId,
        const std::vector<std::string> &pkgContents,
        const std::vector<std::string> &appsGranted,
        const std::vector<std::string> &accessPackages)
{
    useTemplate(APP_RULES_TEMPLATE_FILE_PATH, getApplicationRulesFilePath(appName), appName, pkgName, authorId);

    if (authorId >= 0)
        useTemplate(AUTHOR_RULES_TEMPLATE_FILE_PATH, getAuthorRulesFilePath(authorId), appName, pkgName, authorId);

    updatePackageRules(pkgName, pkgContents, appsGranted);
    generateAppToOtherPackagesDeps(appName, accessPackages);
}

void SmackRules::updatePackageRules(
        const std::string &pkgName,
        const std::vector<std::string> &pkgContents,
        const std::vector<std::string> &appsGranted)
{
    useTemplate(PKG_RULES_TEMPLATE_FILE_PATH, getPackageRulesFilePath(pkgName), std::string(), pkgName);

    SmackRules smackRules;
    std::string pkgPath = getPackageRulesFilePath(pkgName);

    smackRules.generatePackageCrossDeps(pkgContents);
    smackRules.generateAllowOther2XApplicationDeps(pkgName, appsGranted);

    if (smack_smackfs_path() != NULL)
        smackRules.apply();

    smackRules.saveToFile(pkgPath, false);
}

void SmackRules::uninstallPackageRules(const std::string &pkgName)
{
    uninstallRules(getPackageRulesFilePath(pkgName));
}

void SmackRules::uninstallApplicationRules(const std::string &appName)
{
    uninstallRules(getApplicationRulesFilePath(appName));
}

void SmackRules::uninstallRules(const std::string &path)
{
    if (access(path.c_str(), F_OK) == -1) {
        if (errno == ENOENT) {
            LogWarning("Smack rules not found in file: " << path);
            return;
        }

        LogWarning("Cannot access smack rules path: " << path);
        ThrowMsg(SmackException::FileError, "Cannot access smack rules path: " << path);
    }

    try {
        SmackRules rules;
        rules.loadFromFile(path);
        if (smack_smackfs_path())
            rules.clear();
    } catch (const SmackException::Base &e) {
        LogWarning("Failed to clear smack kernel rules from file: " << path);
        // don't stop uninstallation
    }

    if (unlink(path.c_str()) == -1) {
        LogWarning("Failed to remove smack rules file: " << path);
        ThrowMsg(SmackException::FileError, "Failed to remove smack rules file: " << path);
    }
}

void SmackRules::strReplace(std::string &haystack, const std::string &needle,
            const std::string &replace)
{
    size_t pos;
    while ((pos = haystack.find(needle)) != std::string::npos)
        haystack.replace(pos, needle.size(), replace);
}

void SmackRules::uninstallAuthorRules(const int authorId)
{
    uninstallRules(getAuthorRulesFilePath(authorId));
}

void SmackRules::applyPrivateSharingRules(
        const std::string &ownerPkgName,
        const std::vector<std::string> &ownerPkgContents,
        const std::string &targetAppName,
        const std::string &pathLabel,
        bool isPathSharedAlready,
        bool isTargetSharingAlready)
{
    SmackRules rules;
    const std::string &targetLabel = SmackLabels::generateAppLabel(targetAppName);
    if (!isTargetSharingAlready) {

        rules.add(targetLabel,
                  SmackLabels::generatePkgLabel(ownerPkgName),
                  SMACK_APP_DIR_TARGET_PERMS);
    }
    if (!isPathSharedAlready) {
        for (const auto &app: ownerPkgContents) {
            const std::string appLabel = SmackLabels::generateAppLabel(app);
            rules.add(appLabel, pathLabel, SMACK_APP_PATH_OWNER_PERMS);
        }
        rules.add(SMACK_USER, pathLabel, SMACK_APP_PATH_USER_PERMS);
        rules.add(SMACK_SYSTEM, pathLabel, SMACK_APP_PATH_SYSTEM_PERMS);
    }
    rules.add(targetLabel, pathLabel, SMACK_APP_PATH_TARGET_PERMS);
    rules.apply();
}

void SmackRules::dropPrivateSharingRules(
        const std::string &ownerPkgName,
        const std::vector<std::string> &ownerPkgContents,
        const std::string &targetAppName,
        const std::string &pathLabel,
        bool isPathSharedNoMore,
        bool isTargetSharingNoMore)
{
    SmackRules rules;
    const std::string &targetLabel = SmackLabels::generateAppLabel(targetAppName);
    if (isTargetSharingNoMore) {
        rules.addModify(targetLabel,
                  SmackLabels::generatePkgLabel(ownerPkgName),
                  "", SMACK_APP_DIR_TARGET_PERMS);
    }
    if (isPathSharedNoMore) {
        for (const auto &app: ownerPkgContents) {
            const std::string appLabel = SmackLabels::generateAppLabel(app);
            rules.addModify(appLabel, pathLabel, "", SMACK_APP_PATH_OWNER_PERMS);
        }
        rules.addModify(SMACK_USER, pathLabel, "", SMACK_APP_PATH_USER_PERMS);
        rules.addModify(SMACK_SYSTEM, pathLabel, "", SMACK_APP_PATH_SYSTEM_PERMS);
    }
    rules.addModify(targetLabel, pathLabel, "", SMACK_APP_PATH_TARGET_PERMS);
    rules.apply();
}

} // namespace SecurityManager
