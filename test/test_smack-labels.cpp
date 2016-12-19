/*
 *  Copyright (c) 2016 - 2017 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file       test_smack-labels.cpp
 * @author     Dariusz Michaluk (d.michaluk@samsung.com)
 * @version    1.0
 */

#include <boost/test/unit_test.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <linux/xattr.h>
#include <sys/smack.h>

#include <dpl/log/log.h>
#include <smack-labels.h>

using namespace SecurityManager;
using namespace SecurityManager::SmackLabels;

struct FileFixture
{
    FileFixture()
    {
        fd = open(path, O_RDONLY | O_CREAT, 0644);
        BOOST_REQUIRE_MESSAGE(fd > 0, "Failed to open file: " << path);
    }

    ~FileFixture()
    {
        BOOST_WARN_MESSAGE(close(fd) == 0, "Error while closing the file: " << path);
        BOOST_WARN_MESSAGE(unlink(path) == 0, "Error while unlink the file: " << path);
    }

    int fd;
    const static char* path;
};

const char* FileFixture::path = "/tmp/SecurityManagerUTFile";

struct DirectoryFixture
{
    DirectoryFixture()
    {
        int ret = mkdir(directoryPath, S_IRWXU | S_IRWXG | S_IRWXO);
        BOOST_REQUIRE_MESSAGE(ret == 0, "Failed to make directory: " << directoryPath);

        ret = mkdir(subdirectoryPath, S_IRWXU | S_IRWXG | S_IRWXO);
        BOOST_REQUIRE_MESSAGE(ret == 0, "Failed to make directory: " << subdirectoryPath);

        ret = creat(execPath, 0755);
        BOOST_REQUIRE_MESSAGE(ret > 0, "Failed to creat file: " << execPath);

        ret = symlink(execPath, linkPath);
        BOOST_REQUIRE_MESSAGE(ret == 0, "Failed to creat symlink: " << linkPath);
    }

    ~DirectoryFixture()
    {
        const std::string command = "rm -rf " + std::string(directoryPath);
        int ret = system(command.c_str());
        BOOST_WARN_MESSAGE(ret >= 0, "Failed to remove directory: " << directoryPath);
    }

    const static char* directoryPath;
    const static char* subdirectoryPath;
    const static char* execPath;
    const static char* linkPath;

    const std::string getLabel(const char* path, const char* xattr) const;
    bool labelNotExist(const char* path, const char* xattr) const;
};

const char* DirectoryFixture::directoryPath = "/tmp/SecurityManagerUTDirectory/";
const char* DirectoryFixture::subdirectoryPath = "/tmp/SecurityManagerUTDirectory/subdirectory";
const char* DirectoryFixture::execPath = "/tmp/SecurityManagerUTDirectory/exec";
const char* DirectoryFixture::linkPath = "/tmp/SecurityManagerUTDirectory/subdirectory/link";

const std::string DirectoryFixture::getLabel(const char* path, const char* xattr) const
{
    char buffer[SMACK_LABEL_LEN+1] = {};

    int ret = getxattr(path, xattr, buffer, SMACK_LABEL_LEN+1);
    BOOST_REQUIRE_MESSAGE(ret > 0, "Failed to get xattr: " << path);

    return std::string(buffer);
}

bool DirectoryFixture::labelNotExist(const char* path, const char* xattr) const
{
    char buffer[SMACK_LABEL_LEN+1] = {};

    int ret = getxattr(path, xattr, buffer, SMACK_LABEL_LEN+1);

    return ret == -1 ? true : false;
}

BOOST_AUTO_TEST_SUITE(SMACK_LABELS_TEST)

BOOST_FIXTURE_TEST_CASE(T1010_set_get_smack_label_file, FileFixture)
{
    int invalidFd = -1;
    const std::string invalidLabel = "";
    const std::string validLabel = "smack_label";
    const std::string noExistingFilePath = "/tmp/SecurityManagerUTNoExistingFile";

    BOOST_REQUIRE_THROW(setSmackLabelForFd(invalidFd, validLabel), SmackException::FileError);
    BOOST_REQUIRE_THROW(setSmackLabelForFd(fd, invalidLabel), SmackException::FileError);
    BOOST_REQUIRE_THROW(getSmackLabelFromFd(invalidFd), SmackException::Base);
    BOOST_REQUIRE_THROW(getSmackLabelFromPath(noExistingFilePath), SmackException::Base);

    BOOST_REQUIRE_NO_THROW(setSmackLabelForFd(fd, validLabel));
    BOOST_REQUIRE(getSmackLabelFromFd(fd) == validLabel);
    BOOST_REQUIRE(getSmackLabelFromPath(path) == validLabel);
}

BOOST_AUTO_TEST_CASE(T1020_get_smack_label_process)
{
    pid_t pid = -1;
    std::string processLabel, selfLabel;

    BOOST_REQUIRE_THROW(getSmackLabelFromPid(pid), SmackException::Base);
    BOOST_REQUIRE_NO_THROW(selfLabel = getSmackLabelFromSelf());

    pid = getpid();
    BOOST_REQUIRE_NO_THROW(processLabel = getSmackLabelFromPid(pid));
    BOOST_REQUIRE(processLabel == selfLabel);
}

BOOST_AUTO_TEST_CASE(T1030_generate_smack_label)
{
    const std::string invalidAppName = "  ";
    const std::string appName = "appNameT1030";
    const std::string invalidPkgName = "  ";
    const std::string pkgName = "pkgNameT1030";
    const int invalidAuthorId = -1;
    const int validAuthorId = 42;
    const std::string path = "/usr/apps/" + appName + "/shared/";

    const std::string processLabel = "User::Pkg::pkgNameT1030";
    BOOST_REQUIRE_THROW(generateProcessLabel(appName, invalidPkgName, false),
                        SmackException::InvalidLabel);
    BOOST_REQUIRE(generateProcessLabel(appName, pkgName, false) == processLabel);

    const std::string processLabelHybrid = "User::Pkg::pkgNameT1030::App::appNameT1030";
    BOOST_REQUIRE_THROW(generateProcessLabel(appName, invalidPkgName, true),
                        SmackException::InvalidLabel);
    BOOST_REQUIRE_THROW(generateProcessLabel(invalidAppName, pkgName, true),
                        SmackException::InvalidLabel);
    BOOST_REQUIRE_THROW(generateProcessLabel(invalidAppName, invalidPkgName, true),
                        SmackException::InvalidLabel);
    BOOST_REQUIRE(generateProcessLabel(appName, pkgName, true) == processLabelHybrid);

    const std::string pathSharedROLabel = "User::Pkg::pkgNameT1030::SharedRO";
    BOOST_REQUIRE_THROW(generatePathSharedROLabel(invalidPkgName), SmackException::InvalidLabel);
    BOOST_REQUIRE(generatePathSharedROLabel(pkgName) == pathSharedROLabel);

    const std::string pathRWLabel = "User::Pkg::pkgNameT1030";
    BOOST_REQUIRE_THROW(generatePathRWLabel(invalidPkgName), SmackException::InvalidLabel);
    BOOST_REQUIRE(generatePathRWLabel(pkgName) == pathRWLabel);

    const std::string pathROLabel = "User::Pkg::pkgNameT1030::RO";
    BOOST_REQUIRE_THROW(generatePathROLabel(invalidPkgName), SmackException::InvalidLabel);
    BOOST_REQUIRE(generatePathROLabel(pkgName) == pathROLabel);

    const std::string sharedPrivateLabel = "User::Pkg::$1$pkgNameT$j2QeZi5Xvx67DnPfPtwSF.";
    BOOST_REQUIRE(generateSharedPrivateLabel(pkgName, path) == sharedPrivateLabel);

    const std::string pathTrustedLabel = "User::Author::42";
    BOOST_REQUIRE_THROW(generatePathTrustedLabel(invalidAuthorId), SmackException::InvalidLabel);
    BOOST_REQUIRE(generatePathTrustedLabel(validAuthorId) == pathTrustedLabel);
}

BOOST_AUTO_TEST_CASE(T1040_generate_app_pkg_name_from_label)
{
    std::string app, pkg;
    const std::string appName = "appNameT1040";
    const std::string pkgName = "pkgNameT1040";

    std::string invalidLabel = "Admin::Pkg::pkgNameT1040";
    BOOST_REQUIRE_THROW(generateAppPkgNameFromLabel(invalidLabel, app, pkg),
                        SmackException::InvalidLabel);

    invalidLabel = generateProcessLabel(appName, "", false);
    BOOST_REQUIRE_THROW(generateAppPkgNameFromLabel(invalidLabel, app, pkg),
                        SmackException::InvalidLabel);

    std::string validLabel = generateProcessLabel(appName, pkgName, true);
    BOOST_REQUIRE_NO_THROW(generateAppPkgNameFromLabel(validLabel, app, pkg));
    BOOST_REQUIRE(pkg == pkgName);
    BOOST_REQUIRE(app == appName);

    validLabel = generateProcessLabel(appName, pkgName, false);
    BOOST_REQUIRE_NO_THROW(generateAppPkgNameFromLabel(validLabel, app, pkg));
    BOOST_REQUIRE(pkg == pkgName);
    BOOST_REQUIRE(app.empty());
}

BOOST_FIXTURE_TEST_CASE(T1050_setup_path_rw, DirectoryFixture)
{
    const std::string pkgName = "pkgNameT1050";
    const std::string noExistingDirectoryPath = "/tmp/SecurityManagerUTNoExistingDirectory/";
    const int invalidAuthorId = -1;

    BOOST_REQUIRE_THROW(setupPath(pkgName, directoryPath, static_cast<app_install_path_type>(-1)),
                        SmackException::InvalidPathType);
    BOOST_REQUIRE_THROW(setupPath(pkgName, directoryPath, SECURITY_MANAGER_PATH_TRUSTED_RW, invalidAuthorId),
                        SmackException::InvalidParam);
    BOOST_REQUIRE_THROW(setupPath(pkgName, noExistingDirectoryPath, SECURITY_MANAGER_PATH_RW),
                        SmackException::FileError);

    BOOST_REQUIRE_NO_THROW(setupPath(pkgName, directoryPath, SECURITY_MANAGER_PATH_RW));
    const std::string pathRWLabel = generatePathRWLabel(pkgName);

    BOOST_REQUIRE(pathRWLabel == getLabel(directoryPath, XATTR_NAME_SMACK));
    BOOST_REQUIRE(pathRWLabel == getLabel(subdirectoryPath, XATTR_NAME_SMACK));
    BOOST_REQUIRE(pathRWLabel == getLabel(linkPath, XATTR_NAME_SMACK));
    BOOST_REQUIRE(pathRWLabel == getLabel(execPath, XATTR_NAME_SMACK));

    BOOST_REQUIRE("TRUE" == getLabel(directoryPath, XATTR_NAME_SMACKTRANSMUTE));
    BOOST_REQUIRE("TRUE" == getLabel(subdirectoryPath, XATTR_NAME_SMACKTRANSMUTE));

    BOOST_REQUIRE(labelNotExist(execPath, XATTR_NAME_SMACKEXEC));
}

BOOST_FIXTURE_TEST_CASE(T1060_setup_path_ro, DirectoryFixture)
{
    const std::string pkgName = "pkgNameT1060";

    BOOST_REQUIRE_NO_THROW(setupPath(pkgName, directoryPath, SECURITY_MANAGER_PATH_RO));
    const std::string pathROLabel = generatePathROLabel(pkgName);

    BOOST_REQUIRE(pathROLabel == getLabel(directoryPath, XATTR_NAME_SMACK));
    BOOST_REQUIRE(pathROLabel == getLabel(subdirectoryPath, XATTR_NAME_SMACK));
    BOOST_REQUIRE(pathROLabel == getLabel(linkPath, XATTR_NAME_SMACK));
    BOOST_REQUIRE(pathROLabel == getLabel(execPath, XATTR_NAME_SMACK));

    BOOST_REQUIRE(labelNotExist(directoryPath, XATTR_NAME_SMACKTRANSMUTE));
    BOOST_REQUIRE(labelNotExist(subdirectoryPath, XATTR_NAME_SMACKTRANSMUTE));
    BOOST_REQUIRE(labelNotExist(execPath, XATTR_NAME_SMACKEXEC));
}

BOOST_AUTO_TEST_SUITE_END()
