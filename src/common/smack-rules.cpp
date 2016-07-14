/*
 *  Copyright (c) 2014-2016 Samsung Electronics Co., Ltd All Rights Reserved
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
#include <string>
#include <memory>
#include <algorithm>

#include "dpl/log/log.h"
#include "dpl/errno_string.h"
#include "dpl/fstream_accessors.h"
#include "filesystem.h"
#include "smack-labels.h"
#include "tzplatform-config.h"

#include "smack-rules.h"

namespace SecurityManager {

const std::string SMACK_APP_LABEL_TEMPLATE     = "~APP~";
const std::string SMACK_PKG_LABEL_TEMPLATE     = "~PKG~";
const std::string SMACK_AUTHOR_LABEL_TEMPLATE  = "~AUTHOR~";
const std::string APP_RULES_TEMPLATE_FILE_PATH = TizenPlatformConfig::makePath(TZ_SYS_RO_SHARE, "security-manager", "policy", "app-rules-template.smack");
const std::string PKG_RULES_TEMPLATE_FILE_PATH = TizenPlatformConfig::makePath(TZ_SYS_RO_SHARE, "security-manager", "policy", "pkg-rules-template.smack");
const std::string AUTHOR_RULES_TEMPLATE_FILE_PATH = TizenPlatformConfig::makePath(TZ_SYS_RO_SHARE, "security-manager", "policy", "author-rules-template.smack");
const std::string SMACK_RULES_PATH_MERGED      = LOCAL_STATE_DIR "/security-manager/rules-merged/rules.merged";
const std::string SMACK_RULES_PATH_MERGED_T    = LOCAL_STATE_DIR "/security-manager/rules-merged/rules.merged.temp";
const std::string SMACK_RULES_PATH             = LOCAL_STATE_DIR "/security-manager/rules";
const std::string SMACK_RULES_SHARED_RO_PATH   = LOCAL_STATE_DIR "/security-manager/rules/2x_shared_ro";
const std::string SMACK_APP_IN_PACKAGE_PERMS   = "rwxat";
const std::string SMACK_APP_CROSS_PKG_PERMS    = "rx";
const std::string SMACK_APP_PATH_OWNER_PERMS = "rwxat";
const std::string SMACK_APP_PATH_TARGET_PERMS = "rxl";
const std::string SMACK_APP_DIR_TARGET_PERMS = "x";
const std::string SMACK_USER = "User";
const std::string SMACK_SYSTEM = "System";
const std::string SMACK_SYSTEM_PRIVILEGED = "System::Privileged";
const std::string SMACK_APP_PATH_SYSTEM_PERMS = "rwxat";
const std::string SMACK_APP_PATH_USER_PERMS = "rwxat";
const std::string TEMPORARY_FILE_SUFFIX = ".temp";

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
        LogWarning("Error while closing the file: " << path << ", error: " << GetErrnoString(errno));
    }
}

void SmackRules::saveToFile(const std::string &destPath) const
{
    int fd;
    int flags = O_CREAT | O_WRONLY | O_TRUNC;
    std::string path = destPath + TEMPORARY_FILE_SUFFIX;

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
            LogError("I/O Error occured while closing the file: " << path << ", error: " << GetErrnoString(errno));
            unlink(path.c_str());
            ThrowMsg(SmackException::FileError, "I/O Error occured while closing the file: " << path << ", error: " << GetErrnoString(errno));
        } else {
            // non critical error
            // don't change the return code, the descriptor should be closed despite the error.
            LogWarning("Error while closing the file: " << path << ", error: " << GetErrnoString(errno));
        }
    }

    if (0 > rename(path.c_str(), destPath.c_str())) {
        LogError("Error moving file " << path << " to " << destPath << ". Errno: " << GetErrnoString(errno));
        unlink(path.c_str());
        ThrowMsg(SmackException::FileError, "Error moving file " << path << " to " << destPath << ". Errno: " << GetErrnoString(errno));
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

void SmackRules::generateSharedRORules(PkgsApps &pkgsApps)
{
    LogDebug("Generating SharedRO rules");

    SmackRules rules;
    for (size_t i = 0; i < pkgsApps.size(); ++i) {
        for (const std::string &appName : pkgsApps[i].second) {
            std::string appLabel = SmackLabels::generateAppLabel(appName);
            for (size_t j = 0; j < pkgsApps.size(); ++j) {
                if (j != i) { // Rules for SharedRO files from own pkg are generated elsewhere
                    std::string &pkgName = pkgsApps[j].first;
                    rules.add(appLabel,
                        SmackLabels::generatePkgLabelOwnerRWothersRO(pkgName),
                        SMACK_APP_CROSS_PKG_PERMS);
                }
            }
        }
    }

    if (smack_smackfs_path() != NULL)
        rules.apply();

    rules.saveToFile(SMACK_RULES_SHARED_RO_PATH);
}

void SmackRules::revokeSharedRORules(PkgsApps &pkgsApps, const std::string &revokePkg)
{
    LogDebug("Revoking SharedRO rules for target pkg " << revokePkg);

    if (smack_smackfs_path() == NULL)
        return;

    SmackRules rules;
    for (size_t i = 0; i < pkgsApps.size(); ++i) {
        for (const std::string &appName : pkgsApps[i].second) {
            std::string appLabel = SmackLabels::generateAppLabel(appName);
            rules.add(appLabel,
                SmackLabels::generatePkgLabelOwnerRWothersRO(revokePkg),
                SMACK_APP_CROSS_PKG_PERMS);
        }
    }

    rules.clear();
}

std::string SmackRules::getPackageRulesFilePath(const std::string &pkgName)
{
    return std::string(SMACK_RULES_PATH) + "/pkg_" + pkgName;
}

std::string SmackRules::getApplicationRulesFilePath(const std::string &appName)
{
    return std::string(SMACK_RULES_PATH) + "/app_" + appName;
}

std::string SmackRules::getAuthorRulesFilePath(const int authorId)
{
    return std::string(SMACK_RULES_PATH) + "/author_" + std::to_string(authorId);
}

void SmackRules::mergeRules()
{
    int tmp;
    FS::FileNameVector files = FS::getFilesFromDirectory(SMACK_RULES_PATH);

    // remove ignore files with ".temp" suffix
    files.erase(
        std::remove_if(files.begin(), files.end(),
            [&](const std::string &path) -> bool {
                if (path.size() < TEMPORARY_FILE_SUFFIX.size())
                    return false;
                return std::equal(
                    TEMPORARY_FILE_SUFFIX.rbegin(),
                    TEMPORARY_FILE_SUFFIX.rend(),
                    path.rbegin());
            }),
        files.end());

    std::ofstream dst(SMACK_RULES_PATH_MERGED_T, std::ios::binary);

    if (dst.fail()) {
        LogError("Error creating file: " << SMACK_RULES_PATH_MERGED_T);
        ThrowMsg(SmackException::FileError, "Error creating file: " << SMACK_RULES_PATH_MERGED_T);
    }

    for(auto const &e : files) {
        std::ifstream src(std::string(SMACK_RULES_PATH) + "/" + e, std::ios::binary);
        dst << src.rdbuf() << '\n';
        if (dst.bad()) {
            LogError("I/O Error. File " << SMACK_RULES_PATH_MERGED << " will not be updated!");
            unlink(SMACK_RULES_PATH_MERGED_T.c_str());
            ThrowMsg(SmackException::FileError,
                "I/O Error. File " << SMACK_RULES_PATH_MERGED << " will not be updated!");
        }

        if (dst.fail()) {
            // src.rdbuf() was empty
            dst.clear();
        }
    }

    if (dst.flush().fail()) {
        LogError("Error flushing file: " << SMACK_RULES_PATH_MERGED_T);
        unlink(SMACK_RULES_PATH_MERGED_T.c_str());
        ThrowMsg(SmackException::FileError, "Error flushing file: " << SMACK_RULES_PATH_MERGED_T);
    }

    if (0 > fsync(DPL::FstreamAccessors<std::ofstream>::GetFd(dst))) {
        LogError("Error fsync on file: " << SMACK_RULES_PATH_MERGED_T);
        unlink(SMACK_RULES_PATH_MERGED_T.c_str());
        ThrowMsg(SmackException::FileError, "Error fsync on file: " << SMACK_RULES_PATH_MERGED_T);
    }

    dst.close();
    if (dst.fail()) {
        LogError("Error closing file: "  << SMACK_RULES_PATH_MERGED_T);
        unlink(SMACK_RULES_PATH_MERGED_T.c_str());
        ThrowMsg(SmackException::FileError, "Error closing file: " << SMACK_RULES_PATH_MERGED_T);
    }

    if ((tmp = rename(SMACK_RULES_PATH_MERGED_T.c_str(), SMACK_RULES_PATH_MERGED.c_str())) == 0)
        return;

    int err = errno;

    LogError("Error during file rename: "
        << SMACK_RULES_PATH_MERGED_T << " to "
        << SMACK_RULES_PATH_MERGED << " Errno: " << GetErrnoString(err));
    unlink(SMACK_RULES_PATH_MERGED_T.c_str());
    ThrowMsg(SmackException::FileError, "Error during file rename: "
        << SMACK_RULES_PATH_MERGED_T << " to "
        << SMACK_RULES_PATH_MERGED << " Errno: " << GetErrnoString(err));
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
        const std::vector<std::string> &pkgContents)
{
    useTemplate(APP_RULES_TEMPLATE_FILE_PATH, getApplicationRulesFilePath(appName), appName, pkgName, authorId);

    if (authorId >= 0)
        useTemplate(AUTHOR_RULES_TEMPLATE_FILE_PATH, getAuthorRulesFilePath(authorId), appName, pkgName, authorId);

    updatePackageRules(pkgName, pkgContents);
}

void SmackRules::updatePackageRules(
        const std::string &pkgName,
        const std::vector<std::string> &pkgContents)
{
    SmackRules smackRules;
    smackRules.addFromTemplateFile(
            PKG_RULES_TEMPLATE_FILE_PATH,
            std::string(),
            pkgName,
            -1);

    smackRules.generatePackageCrossDeps(pkgContents);

    if (smack_smackfs_path() != NULL)
        smackRules.apply();

    smackRules.saveToFile(getPackageRulesFilePath(pkgName));
}


void SmackRules::revokeAppSubject(const std::string &appName)
{
    if (smack_revoke_subject(SmackLabels::generateAppLabel(appName).c_str()))
        ThrowMsg(SmackException::LibsmackError, "smack_revoke_subject");
}

void SmackRules::uninstallPackageRules(const std::string &pkgName)
{
    uninstallRules(getPackageRulesFilePath(pkgName));
}

void SmackRules::uninstallApplicationRules(const std::string &appName)
{
    uninstallRules(getApplicationRulesFilePath(appName));
    revokeAppSubject(appName);
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
        rules.add(SMACK_SYSTEM_PRIVILEGED, pathLabel, SMACK_APP_PATH_SYSTEM_PERMS);
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
        rules.addModify(SMACK_SYSTEM_PRIVILEGED, pathLabel, "", SMACK_APP_PATH_SYSTEM_PERMS);
    }
    rules.addModify(targetLabel, pathLabel, "", SMACK_APP_PATH_TARGET_PERMS);
    rules.apply();
}

} // namespace SecurityManager
