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
#include <smack-common.h>

#include "security-manager.h"
#include "smack-labels.h"

namespace SecurityManager {

/* Const defined below is used to label links to executables */
const char *const LABEL_FOR_PUBLIC_APP_PATH = "User";

enum class FileDecision {
    SKIP = 0,
    LABEL = 1,
    ERROR = -1
};

typedef std::function<FileDecision(const FTSENT*)> LabelDecisionFn;

static FileDecision labelAll(const FTSENT *ftsent __attribute__((unused)))
{
    return FileDecision::LABEL;
}

static FileDecision labelDirs(const FTSENT *ftsent)
{
    // label only directories
    if (S_ISDIR(ftsent->fts_statp->st_mode))
        return FileDecision::LABEL;
    return FileDecision::SKIP;
}

static FileDecision labelExecs(const FTSENT *ftsent)
{
    // LogDebug("Mode = " << ftsent->fts_statp->st_mode); // this could be helpfull in debugging
    // label only regular executable files
    if (S_ISREG(ftsent->fts_statp->st_mode) && (ftsent->fts_statp->st_mode & S_IXUSR))
        return FileDecision::LABEL;
    return FileDecision::SKIP;
}

static FileDecision labelLinksToExecs(const FTSENT *ftsent)
{
    struct stat buf;

    // check if it's a link
    if ( !S_ISLNK(ftsent->fts_statp->st_mode))
        return FileDecision::SKIP;

    std::unique_ptr<char, std::function<void(void*)>> target(realpath(ftsent->fts_path, NULL), free);

    if (!target.get()) {
        LogError("Getting link target for " << ftsent->fts_path << " failed (Error = " << strerror(errno) << ")");
        return FileDecision::ERROR;
    }

    if (-1 == stat(target.get(), &buf)) {
        LogError("stat failed for " << target.get() << " (Error = " << strerror(errno) << ")");
        return FileDecision::ERROR;
    }
    // skip if link target is not a regular executable file
    if (buf.st_mode != (buf.st_mode | S_IXUSR | S_IFREG)) {
        // LogDebug(target.get() << "is not a regular executable file. Skipping.");
        return FileDecision::SKIP;
    }

    return FileDecision::LABEL;
}

static bool dirSetSmack(const std::string &path, const std::string &label,
        const char *xattr_name, LabelDecisionFn fn)
{
    char *const path_argv[] = {const_cast<char *>(path.c_str()), NULL};
    FTSENT *ftsent;
    FileDecision ret;

    std::unique_ptr<FTS, std::function<void(FTS*)> > fts(
            fts_open(path_argv, FTS_PHYSICAL | FTS_NOCHDIR, NULL),
            fts_close);

    if (fts.get() == NULL) {
        LogError("fts_open failed.");
        return false;
    }

    while ((ftsent = fts_read(fts.get())) != NULL) {
        /* Check for error (FTS_ERR) or failed stat(2) (FTS_NS) */
        if (ftsent->fts_info == FTS_ERR || ftsent->fts_info == FTS_NS) {
            LogError("FTS_ERR error or failed stat(2) (FTS_NS)");
            return false;
        }

        ret = fn(ftsent);
        if (ret == FileDecision::ERROR) {
            LogError("fn(ftsent) failed.");
            return false;
        }

        if (ret == FileDecision::LABEL) {
            if (lsetxattr(ftsent->fts_path, xattr_name, label.c_str(), label.length(), 0) != 0) {
                LogError("lsetxattr failed.");
                return false;
            }
        }

    }

    /* If last call to fts_read() set errno, we need to return error. */
    if ((errno != 0) && (ftsent == NULL)) {
        LogError("Last errno from fts_read: " << strerror(errno));
        return false;
    }
    return true;
}


static bool labelDir(const std::string &path, const std::string &label,
        bool set_transmutable, bool set_executables)
{
    bool ret = true;

    // setting access label on everything in given directory and below
    ret = dirSetSmack(path, label, XATTR_NAME_SMACK, labelAll);
    if (!ret) {
        LogError("dirSetSmack failed (access label)");
        return ret;
    }

    if (set_transmutable) {
        // setting transmute on dirs
        ret = dirSetSmack(path, "TRUE", XATTR_NAME_SMACKTRANSMUTE, labelDirs);
        if (!ret) {
            LogError("dirSetSmack failed (transmute)");
            return ret;
        }
    }

    if (set_executables) {
        ret = dirSetSmack(path, label, XATTR_NAME_SMACKEXEC, &labelExecs);
        if (!ret)
        {
            LogError("dirSetSmack failed (execs).");
            return ret;
        }

        //setting execute label for everything with permission to execute
        ret = dirSetSmack(path, label, XATTR_NAME_TIZENEXEC, &labelLinksToExecs);
        if (!ret)
        {
            LogError("dirSetSmack failed (link to execs).");
            return ret;
        }
    }

    return ret;
}

bool setupPath(const std::string &pkgId, const std::string &path,
    app_install_path_type pathType)
{
    std::string label;
    bool label_executables, label_transmute;

    switch (pathType) {
    case SECURITY_MANAGER_PATH_PRIVATE:
        if (!generateAppLabel(pkgId, label))
            return false;
        label_executables = true;
        label_transmute = false;
        break;
    case SECURITY_MANAGER_PATH_PUBLIC:
        label.assign(LABEL_FOR_PUBLIC_APP_PATH);
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
        return false;
    }
    return labelDir(path, label, label_transmute, label_executables);
}

} // namespace SecurityManager
