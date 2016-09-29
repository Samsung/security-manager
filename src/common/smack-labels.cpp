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
 * @file        smack-labels.cpp
 * @author      Jan Cybulski <j.cybulski@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Implementation of functions managing smack labels
 *
 */

#include <crypt.h>
#include <sys/stat.h>
#include <sys/smack.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <memory>
#include <fts.h>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <string>
#include <sstream>
#include <algorithm>

#include <dpl/log/log.h>
#include <dpl/errno_string.h>

#include "security-manager.h"
#include "smack-labels.h"
#include "utils.h"


namespace SecurityManager {
namespace SmackLabels {

//! Smack label used for SECURITY_MANAGER_PATH_PUBLIC_RO paths (RO for all apps)
const char *const LABEL_FOR_APP_PUBLIC_RO_PATH = "User::Home";

typedef std::function<bool(const FTSENT*)> LabelDecisionFn;

static bool labelAll(const FTSENT *ftsent __attribute__((unused)))
{
    return true;
}

static bool labelDirs(const FTSENT *ftsent)
{
    // label only directories
    return (S_ISDIR(ftsent->fts_statp->st_mode));
}

static bool labelExecs(const FTSENT *ftsent)
{
    // LogDebug("Mode = " << ftsent->fts_statp->st_mode); // this could be helpfull in debugging
    // label only regular executable files
    return (S_ISREG(ftsent->fts_statp->st_mode) && (ftsent->fts_statp->st_mode & S_IXUSR));
}

static inline void pathSetSmack(const char *path, const std::string &label,
        const char *xattr_name)
{
    if (lsetxattr(path, xattr_name, label.c_str(), label.length(), 0)) {
        LogError("lsetxattr failed.");
        ThrowMsg(SmackException::FileError, "lsetxattr failed.");
    }
}

static void dirSetSmack(const std::string &path, const std::string &label,
        const char *xattr_name, LabelDecisionFn fn)
{
    char *const path_argv[] = {const_cast<char *>(path.c_str()), NULL};
    FTSENT *ftsent;

    auto fts = makeUnique(fts_open(path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL), fts_close);
    if (!fts) {
        LogError("fts_open failed.");
        ThrowMsg(SmackException::FileError, "fts_open failed.");
    }

    while ((ftsent = fts_read(fts.get())) != NULL) {
        /* Check for error (FTS_ERR) or failed stat(2) (FTS_NS) */
        if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
            LogError("FTS_ERR error or failed stat(2) (FTS_NS)");
            ThrowMsg(SmackException::FileError, "FTS_ERR error or failed stat(2) (FTS_NS)");
        }

        /* avoid to tag directories two times */
        if (ftsent->fts_info == FTS_D)
            continue;

        if (fn(ftsent))
            pathSetSmack(ftsent->fts_path, label, xattr_name);
    }

    /* If last call to fts_read() set errno, we need to return error. */
    if ((errno != 0) && (ftsent == NULL)) {
        LogError("Last errno from fts_read: " << GetErrnoString(errno));
        ThrowMsg(SmackException::FileError, "Last errno from fts_read: " << GetErrnoString(errno));
    }
}

static void labelDir(const std::string &path, const std::string &label,
        bool set_transmutable, bool set_executables)
{
    // setting access label on everything in given directory and below
    dirSetSmack(path, label, XATTR_NAME_SMACK, labelAll);

    // setting transmute on dirs
    if (set_transmutable)
        dirSetSmack(path, "TRUE", XATTR_NAME_SMACKTRANSMUTE, labelDirs);

    // setting SMACK64EXEC labels
    if (set_executables)
        dirSetSmack(path, label, XATTR_NAME_SMACKEXEC, &labelExecs);
}

void setupPath(
        const std::string &pkgName,
        const std::string &path,
        app_install_path_type pathType,
        const int authorId)
{
    std::string label;
    bool label_executables, label_transmute;

    switch (pathType) {
    case SECURITY_MANAGER_PATH_RW:
        label = generatePathRWLabel(pkgName);
        label_executables = false;
        label_transmute = true;
        break;
    case SECURITY_MANAGER_PATH_RO:
        label = generatePathROLabel(pkgName);
        label_executables = false;
        label_transmute = false;
        break;
    case SECURITY_MANAGER_PATH_PUBLIC_RO:
        label.assign(LABEL_FOR_APP_PUBLIC_RO_PATH);
        label_executables = false;
        label_transmute = true;
        break;
    case SECURITY_MANAGER_PATH_OWNER_RW_OTHER_RO:
        label = generatePathSharedROLabel(pkgName);
        label_executables = false;
        label_transmute = true;
        break;
    case SECURITY_MANAGER_PATH_TRUSTED_RW:
        if (authorId < 0)
            ThrowMsg(SmackException::InvalidParam, "You must define author to use PATH_TRUSED_RW");
        label = generatePathTrustedLabel(authorId);
        label_executables = false;
        label_transmute = true;
        break;
    default:
        LogError("Path type not known.");
        Throw(SmackException::InvalidPathType);
    }
    return labelDir(path, label, label_transmute, label_executables);
}

void setupPkgBasePath(const std::string &basePath)
{
    pathSetSmack(basePath.c_str(), LABEL_FOR_APP_PUBLIC_RO_PATH, XATTR_NAME_SMACK);
}

void setupSharedPrivatePath(const std::string &pkgName, const std::string &path) {
    pathSetSmack(path.c_str(), generateSharedPrivateLabel(pkgName, path), XATTR_NAME_SMACK);
}

void generateAppPkgNameFromLabel(const std::string &label, std::string &appName, std::string &pkgName)
{
    static const char pkgPrefix[] = "User::Pkg::";
    static const char appPrefix[] = "::App::";

    if (label.compare(0, sizeof(pkgPrefix) - 1, pkgPrefix))
        ThrowMsg(SmackException::InvalidLabel, "Invalid application process label " << label);

    size_t pkgStartPos = sizeof(pkgPrefix) - 1;
    size_t pkgEndPos = label.find(appPrefix, pkgStartPos);
    if (pkgEndPos != std::string::npos) {
        LogDebug("Hybrid application process label");
        size_t appStartPos = pkgEndPos + sizeof(appPrefix) - 1;
        appName = label.substr(appStartPos, std::string::npos);
        pkgName = label.substr(pkgStartPos, pkgEndPos - pkgStartPos);
    } else {
        pkgName = label.substr(pkgStartPos, std::string::npos);
    }

    if (pkgName.empty())
        ThrowMsg(SmackException::InvalidLabel, "No pkgName in Smack label " << label);
}

std::string generateProcessLabel(const std::string &appName, const std::string &pkgName,
                                 bool isHybrid)
{
    std::string label = "User::Pkg::" + pkgName;
    if (isHybrid)
        label += "::App::" + appName;

    if (smack_label_length(label.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Invalid Smack label generated from appName " << appName);

    return label;
}

std::string generatePathSharedROLabel(const std::string &pkgName)
{
    std::string label = "User::Pkg::" + pkgName + "::SharedRO";

    if (smack_label_length(label.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Invalid Smack label generated from pkgName " << pkgName);

    return label;
}

std::string generatePathRWLabel(const std::string &pkgName)
{
    std::string label = "User::Pkg::" + pkgName;

    if (smack_label_length(label.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Invalid Smack label generated from pkgName " << pkgName);

    return label;
}

std::string generatePathROLabel(const std::string &pkgName)
{
    std::string label = "User::Pkg::" + pkgName + "::RO";

    if (smack_label_length(label.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Invalid Smack label generated from pkgName " << pkgName);

    return label;
}

std::string generateSharedPrivateLabel(const std::string &pkgName, const std::string &path)
{
    // Prefix $1$ causes crypt() to use MD5 function
    std::string label = "User::Pkg::";
    std::string salt = "$1$" + pkgName;

    const char * cryptLabel = crypt(path.c_str(), salt.c_str());
    if (!cryptLabel) {
        ThrowMsg(SmackException::Base, "crypt error");
    }
    label += cryptLabel;
    std::replace(label.begin(), label.end(), '/', '%');
    if (smack_label_length(label.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Invalid Smack label generated from path " << path);
    return label;
}

template<typename FuncType, typename... ArgsType>
static std::string getSmackLabel(FuncType func, ArgsType... args)
{
    char *label;
    ssize_t labelLen = func(args..., &label);
    if (labelLen <= 0)
        ThrowMsg(SmackException::Base, "Error while getting Smack label");
    auto labelPtr = makeUnique(label, free);
    return std::string(labelPtr.get(), labelLen);
}

std::string getSmackLabelFromSocket(int socketFd)
{
    return getSmackLabel(&smack_new_label_from_socket, socketFd);
}

std::string getSmackLabelFromPath(const std::string &path)
{
    return getSmackLabel(&smack_new_label_from_path, path.c_str(), XATTR_NAME_SMACK, true);
}

std::string getSmackLabelFromSelf(void)
{
    return getSmackLabel(&smack_new_label_from_self);
}

std::string getSmackLabelFromPid(pid_t pid)
{
    // FIXME: libsmack should provide such a function
    std::ifstream smackFileStream("/proc/" + std::to_string(pid) + "/attr/current");
    if (!smackFileStream.is_open())
        ThrowMsg(SmackException::FileError,
                "/attr/current file open error for pid: " << pid);

    std::string result;
    if (!std::getline(smackFileStream, result))
        ThrowMsg(SmackException::FileError,
                "/attr/current file read error for pid: " << pid);

    if (smack_label_length(result.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Error while fetching Smack label for process " << pid);

    return result;
}

std::string generatePathTrustedLabel(const int authorId)
{
    if (authorId < 0) {
        LogError("Author was not set. It's not possible to generate label for unknown author.");
        ThrowMsg(SmackException::InvalidLabel, "Could not generate valid label without authorId");
    }

    return "User::Author::" + std::to_string(authorId);
}

} // namespace SmackLabels
} // namespace SecurityManager
