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
#include <dirent.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <fcntl.h>
#include <fstream>
#include <cstring>
#include <sstream>

#include <dpl/log/log.h>
#include <tzplatform_config.h>

#include "smack-labels.h"
#include "smack-rules.h"

namespace SecurityManager {

const char *const SMACK_APP_LABEL_TEMPLATE     = "~APP~";
const char *const SMACK_PKG_LABEL_TEMPLATE     = "~PKG~";
const char *const APP_RULES_TEMPLATE_FILE_PATH = tzplatform_mkpath(TZ_SYS_SMACK, "app-rules-template.smack");
const char *const SMACK_APP_IN_PACKAGE_PERMS   = "rwxat";

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

bool SmackRules::add(const std::string &subject, const std::string &object,
        const std::string &permissions)
{
    return 0 == smack_accesses_add(m_handle, subject.c_str(), object.c_str(), permissions.c_str());
}

bool SmackRules::addModify(const std::string &subject, const std::string &object,
        const std::string &allowPermissions, const std::string &denyPermissions)
{
    return 0 == smack_accesses_add_modify(m_handle, subject.c_str(), object.c_str(), allowPermissions.c_str(), denyPermissions.c_str());
}

bool SmackRules::clear() const
{
    return 0 == smack_accesses_clear(m_handle);
}

bool SmackRules::apply() const
{
    return 0 == smack_accesses_apply(m_handle);
}

bool SmackRules::loadFromFile(const std::string &path)
{
    int fd;
    bool ret = true;

    fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_RDONLY));
    if (fd == -1) {
        LogError("Failed to open file: " << path);
        return false;
    }

    if (smack_accesses_add_from_file(m_handle, fd)) {
        LogError("Failed to load smack rules from file: " << path);
        ret = false;
    }

    if (close(fd) == -1) {
        // don't change the return code, the descriptor should be closed despite the error.
        LogWarning("Error while closing the file: " << path << ", error: " << strerror(errno));
    }

    return ret;
}

bool SmackRules::saveToFile(const std::string &path) const
{
    int fd;
    bool ret = true;

    fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644));
    if (fd == -1) {
        LogError("Failed to create file: " << path);
        return false;
    }

    if (smack_accesses_save(m_handle, fd)) {
        LogError("Failed to save rules to file: " << path);
        unlink(path.c_str());
        ret = false;
    }

    if (close(fd) == -1) {
        if (errno == EIO) {
            LogError("I/O Error occured while closing the file: " << path << ", error: " << strerror(errno));
            unlink(path.c_str());
            return false;
        } else {
            // non critical error
            // don't change the return code, the descriptor should be closed despite the error.
            LogWarning("Error while closing the file: " << path << ", error: " << strerror(errno));
        }
    }

    return ret;
}


bool SmackRules::addFromTemplateFile(const std::string &appId,
        const std::string &pkgId)
{
    std::vector<std::string> templateRules;
    std::string line;
    std::ifstream templateRulesFile(APP_RULES_TEMPLATE_FILE_PATH);

    if (!templateRulesFile.is_open()) {
        LogError("Cannot open rules template file: " << APP_RULES_TEMPLATE_FILE_PATH);
        return false;
    }

    while (std::getline(templateRulesFile, line)) {
        templateRules.push_back(line);
    }

    if (templateRulesFile.bad()) {
        LogError("Error reading template file: " << APP_RULES_TEMPLATE_FILE_PATH);
        return false;
    }

    return addFromTemplate(templateRules, appId, pkgId);
}

bool SmackRules::addFromTemplate(const std::vector<std::string> &templateRules,
        const std::string &appId, const std::string &pkgId)
{
    for (auto rule : templateRules) {
        if (rule.empty())
            continue;

        std::stringstream stream(rule);
        std::string subject, object, permissions;
        stream >> subject >> object >> permissions;

        if (stream.fail() || !stream.eof()) {
            LogError("Invalid rule template: " << rule);
            return false;
        }

        if (subject == SMACK_APP_LABEL_TEMPLATE) {
            if (!generateAppLabel(appId, subject)) {
                LogError("Failed to generate app label from appId: " << appId);
                return false;
            }
        }

        if (subject == SMACK_PKG_LABEL_TEMPLATE) {
            if (!generatePkgLabel(pkgId, object)) {
                LogError("Failed to generate pkg label from pkgid: " << pkgId);
                return false;
            }
        }

        if (object == SMACK_APP_LABEL_TEMPLATE) {
            if (!generateAppLabel(appId, object)) {
                LogError("Failed to generate app label from appId: " << appId);
                return false;
            }
        }

        if (object == SMACK_PKG_LABEL_TEMPLATE) {
            if (!generatePkgLabel(pkgId, object)) {
                LogError("Failed to generate pkg label from pkgId: " << pkgId);
                return false;
            }
        }

        if (!add(subject, object, permissions)) {
            LogError("Failed to add rule: " << subject << " " << object << " " << permissions);
            return false;
        }
    }

    return true;
}

bool SmackRules::generatePackageCrossDeps(const std::vector<std::string> &pkgContents)
{
    LogDebug ("Generating cross-package rules");

    std::string subjectLabel, objectLabel;
    std::string appsInPackagePerms = SMACK_APP_IN_PACKAGE_PERMS;

    for (const auto &subject : pkgContents) {
        for (const auto &object : pkgContents) {
            if (object == subject)
                continue;

            if (generateAppLabel(subject, subjectLabel) && generateAppLabel(object, objectLabel)) {
                LogDebug ("Trying to add rule subject: " << subjectLabel << " object: " << objectLabel
                            << " perms: " << appsInPackagePerms);
                if (!add (subjectLabel, objectLabel, appsInPackagePerms)) {
                    LogError ("Can't add in-package rule for subject: "
                                << subject << " and object: " << object);
                    return false;
                }
            }
            else {
                LogError ("Failed to created smack labels for subject: "
                            << subject << " and object: " << object);
                return false;
            }
        }
    }

    return true;
}

std::string SmackRules::getPackageRulesFilePath(const std::string &pkgId)
{
    std::string path(tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d", ("pkg_" + pkgId).c_str()));
    return path;
}

std::string SmackRules::getApplicationRulesFilePath(const std::string &appId)
{
    std::string path(tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d", ("app_" +  appId).c_str()));
    return path;
}

bool SmackRules::installApplicationRules(const std::string &appId, const std::string &pkgId,
        const std::vector<std::string> &pkgContents) {
    try {
        SmackRules smackRules;
        std::string appPath = getApplicationRulesFilePath(appId);

        if (!smackRules.addFromTemplateFile(appId, pkgId)) {
            LogError("Failed to load smack rules for appId: " << appId << " with pkgId: " << pkgId);
            return false;
        }

        if (smack_smackfs_path() != NULL && !smackRules.apply()) {
            LogError("Failed to apply application rules to kernel [app]");
            return false;
        }

        if (!smackRules.saveToFile(appPath)) {
            smackRules.clear();
            return false;
        }

        if (!updatePackageRules(pkgId, pkgContents))
        {
            return false;
        }

        return true;
    } catch (const std::bad_alloc &e) {
        LogError("Out of memory while trying to install smack rules for appId: "
                << appId << "in pkgId: " << pkgId);
        return false;
    }
}

bool SmackRules::updatePackageRules(const std::string &pkgId, const std::vector<std::string> &pkgContents)
{
    try {
        SmackRules smackRules;
        std::string pkgPath = getPackageRulesFilePath(pkgId);

        if (!smackRules.generatePackageCrossDeps(pkgContents))
        {
            LogError("Failed to create application in-package cross dependencies");
            return false;
        }

        if (smack_smackfs_path() != NULL && !smackRules.apply()) {
             LogError("Failed to apply application rules to kernel [pkg]");
             return false;
         }

         if (!smackRules.saveToFile(pkgPath)) {
             smackRules.clear();
             return false;
         }

         return true;
    } catch (const std::bad_alloc &e) {
        LogError("Out of memory while trying to install smack rules for pkgId: " << pkgId);
        return false;
    }
}

/* FIXME: Remove this function if real pkgId instead of "User" label will be used
 * in generateAppLabel(). */
bool SmackRules::addMissingRulesFix()
{
    DIR *dir;
    struct dirent *ent;
    SmackRules rules;
    std::string path(tzplatform_mkpath(TZ_SYS_SMACK, "accesses.d"));

    dir = opendir(path.c_str());
    if (dir != NULL) {
        while ((ent = readdir(dir))) {
            if (ent->d_type == DT_REG) {
                rules.loadFromFile(tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d/", ent->d_name));
                // Do not check error here. If this fails we can't do anything anyway.
            }
        }
        rules.apply();
    }
    else
        return false;

    closedir(dir);

    return true;
}

bool SmackRules::uninstallPackageRules(const std::string &pkgId)
{
    if (!uninstallRules(getPackageRulesFilePath(pkgId)))
    {
        LogError("Failed to uninstall application rules for pkgId: " << pkgId);
        return false;
    }

    return true;
}

bool SmackRules::uninstallApplicationRules(const std::string &appId,
        const std::string &pkgId, std::vector<std::string> pkgContents)
{
    if (!uninstallRules (getApplicationRulesFilePath(appId)))
    {
        LogError("Failed to uninstall application rules for appId: " << appId);
        return false;
    }

    if (!updatePackageRules(pkgId, pkgContents))
    {
        LogError("failed to update package rules for appId: " << appId
                << " pkgId: " << pkgId);
        return false;
    }

    // FIXME: Reloading all rules:
    SmackRules::addMissingRulesFix();

    return true;
}

bool SmackRules::uninstallRules(const std::string &path)
{
    if (access(path.c_str(), F_OK) == -1) {
        if (errno == ENOENT) {
            LogWarning("Smack rules not found in file: " << path);
            return true;
        }

        LogWarning("Cannot access smack rules path: " << path);
        return false;
    }

    try {
        SmackRules rules;
        if (rules.loadFromFile(path)) {
            if (smack_smackfs_path() != NULL && !rules.clear()) {
                LogWarning("Failed to clear smack kernel rules from file: " << path);
                // don't stop uninstallation
            }
        } else {
            LogWarning("Failed to load rules from file: " << path);
            // don't stop uninstallation
        }

        if (unlink(path.c_str()) == -1) {
            LogError("Failed to remove smack rules file: " << path);
            return false;
        }
    } catch (const std::bad_alloc &e) {
        LogError("Out of memory while trying to uninstall smack rules from path: " << path);
        return false;
    }
    return true;
}

} // namespace SecurityManager

