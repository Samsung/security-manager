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
#include <memory>

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

void SmackRules::saveToFile(const std::string &path) const
{
    int fd;

    fd = TEMP_FAILURE_RETRY(open(path.c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0644));
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


void SmackRules::addFromTemplateFile(const std::string &appId,
        const std::string &pkgId)
{
    std::vector<std::string> templateRules;
    std::string line;
    std::ifstream templateRulesFile(APP_RULES_TEMPLATE_FILE_PATH);

    if (!templateRulesFile.is_open()) {
        LogError("Cannot open rules template file: " << APP_RULES_TEMPLATE_FILE_PATH);
        ThrowMsg(SmackException::FileError, "Cannot open rules template file: " << APP_RULES_TEMPLATE_FILE_PATH);
    }

    while (std::getline(templateRulesFile, line)) {
        templateRules.push_back(line);
    }

    if (templateRulesFile.bad()) {
        LogError("Error reading template file: " << APP_RULES_TEMPLATE_FILE_PATH);
        ThrowMsg(SmackException::FileError, "Error reading template file: " << APP_RULES_TEMPLATE_FILE_PATH);
    }

    addFromTemplate(templateRules, appId, pkgId);
}

void SmackRules::addFromTemplate(const std::vector<std::string> &templateRules,
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
            ThrowMsg(SmackException::FileError, "Invalid rule template: " << rule);
        }

        if (subject == SMACK_APP_LABEL_TEMPLATE)
            subject = SmackLabels::generateAppLabel(appId);

        if (subject == SMACK_PKG_LABEL_TEMPLATE)
             subject = SmackLabels::generatePkgLabel(pkgId);

        if (object == SMACK_APP_LABEL_TEMPLATE)
            object = SmackLabels::generateAppLabel(appId);

        if (object == SMACK_PKG_LABEL_TEMPLATE)
            object = SmackLabels::generatePkgLabel(pkgId);

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

void SmackRules::installApplicationRules(const std::string &appId, const std::string &pkgId,
        const std::vector<std::string> &pkgContents)
{
    SmackRules smackRules;
    std::string appPath = getApplicationRulesFilePath(appId);

    smackRules.addFromTemplateFile(appId, pkgId);

    if (smack_smackfs_path() != NULL)
        smackRules.apply();

    smackRules.saveToFile(appPath);
    updatePackageRules(pkgId, pkgContents);
}

void SmackRules::updatePackageRules(const std::string &pkgId, const std::vector<std::string> &pkgContents)
{
    SmackRules smackRules;
    std::string pkgPath = getPackageRulesFilePath(pkgId);

    smackRules.generatePackageCrossDeps(pkgContents);

    if (smack_smackfs_path() != NULL)
        smackRules.apply();

    smackRules.saveToFile(pkgPath);
}

/* FIXME: Remove this function if real pkgId instead of "User" label will be used
 * in generateAppLabel(). */
void SmackRules::addMissingRulesFix()
{
    struct dirent *ent;

    std::string path(tzplatform_mkpath(TZ_SYS_SMACK, "accesses.d"));
    std::unique_ptr<DIR, std::function<int(DIR*)>> dir(opendir(path.c_str()), closedir);
    if (!dir)
        ThrowMsg(SmackException::FileError, "opendir");

    while ((ent = readdir(dir.get()))) {
        SmackRules rules;
        if (ent->d_type == DT_REG) {
            rules.loadFromFile(tzplatform_mkpath3(TZ_SYS_SMACK, "accesses.d/", ent->d_name));
            // Do not check error here. If this fails we can't do anything anyway.
        }
        rules.apply();
    }
}

void SmackRules::uninstallPackageRules(const std::string &pkgId)
{
    uninstallRules(getPackageRulesFilePath(pkgId));
}

void SmackRules::uninstallApplicationRules(const std::string &appId,
        const std::string &pkgId, std::vector<std::string> pkgContents)
{
    uninstallRules(getApplicationRulesFilePath(appId));
    updatePackageRules(pkgId, pkgContents);

    // FIXME: Reloading all rules:
    SmackRules::addMissingRulesFix();
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

} // namespace SecurityManager
