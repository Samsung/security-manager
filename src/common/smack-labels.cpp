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
 * @file        smack-labels.cpp
 * @author      Jan Cybulski <j.cybulski@samsung.com>
 * @author      Rafal Krypa <r.krypa@samsung.com>
 * @version     1.0
 * @brief       Implementation of functions managing smack labels
 *
 */

#include <sys/stat.h>
#include <sys/smack.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <memory>
#include <fts.h>
#include <cstring>
#include <string>

#include <dpl/log/log.h>

#include "security-manager.h"
#include "smack-labels.h"
#include "zone-utils.h"

namespace SecurityManager {
namespace SmackLabels {

/* Const defined below is used to label files accessible to apps only for reading */
const char *const LABEL_FOR_APP_RO_PATH = "User::Home";

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

    std::unique_ptr<FTS, std::function<void(FTS*)> > fts(
            fts_open(path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL),
            fts_close);

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
        LogError("Last errno from fts_read: " << strerror(errno));
        ThrowMsg(SmackException::FileError, "Last errno from fts_read: " << strerror(errno));
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

void setupPath(const std::string &appId, const std::string &path, app_install_path_type pathType)
{
    setupPath(appId, path, pathType, std::string());
}

void setupPath(const std::string &appId, const std::string &path, app_install_path_type pathType,
        const std::string &zoneId)
{
    std::string label;
    bool label_executables, label_transmute;

    switch (pathType) {
    case SECURITY_MANAGER_PATH_PRIVATE:
    case SECURITY_MANAGER_PATH_RW:
        label = zoneSmackLabelGenerate(generateAppLabel(appId), zoneId);
        label_executables = true;
        label_transmute = false;
        break;
    case SECURITY_MANAGER_PATH_PUBLIC:
    case SECURITY_MANAGER_PATH_RO:
        label.assign(LABEL_FOR_APP_RO_PATH);
        label_executables = false;
        label_transmute = true;
        break;
    case SECURITY_MANAGER_PATH_PUBLIC_RO:
        label.assign("_");
        label_executables = false;
        label_transmute = false;
        break;
    default:
        LogError("Path type not known.");
        Throw(SmackException::InvalidPathType);
    }
    return labelDir(path, label, label_transmute, label_executables);
}

void setupCorrectPath(const std::string &pkgId, const std::string &appId, const std::string &basePath)
{
    setupCorrectPath(pkgId, appId, basePath, std::string());
}

void setupCorrectPath(const std::string &pkgId, const std::string &appId, const std::string &basePath,
        const std::string& zoneId)
{
    std::string pkgPath = basePath + "/" + pkgId;
    std::string appPath = pkgPath + "/" + appId;

    pathSetSmack(pkgPath.c_str(), zoneSmackLabelGenerate(generatePkgLabel(pkgId), zoneId), XATTR_NAME_SMACK);
    pathSetSmack(appPath.c_str(), zoneSmackLabelGenerate(generateAppLabel(appId), zoneId), XATTR_NAME_SMACK);
    pathSetSmack(appPath.c_str(), "TRUE", XATTR_NAME_SMACKTRANSMUTE);
}

std::string generateAppNameFromLabel(const std::string &label)
{
    static const char prefix[] = "User::App::";

    if (label.compare(0, sizeof(prefix) - 1, prefix))
        ThrowMsg(SmackException::InvalidLabel, "Cannot extract appId from Smack label " << label);

    return label.substr(sizeof(prefix) - 1);
}

std::string generateAppLabel(const std::string &appId)
{
    std::string label = "User::App::" + appId;

    if (smack_label_length(label.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Invalid Smack label generated from appId " << appId);

    return label;
}

std::string generatePkgLabel(const std::string &pkgId)
{
    std::string label = "User::Pkg::" + pkgId;

    if (smack_label_length(label.c_str()) <= 0)
        ThrowMsg(SmackException::InvalidLabel, "Invalid Smack label generated from pkgId " << pkgId);

    return label;
}

} // namespace SmackLabels
} // namespace SecurityManager
