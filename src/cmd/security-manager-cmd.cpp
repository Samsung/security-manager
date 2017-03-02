/*
 *  Copyright (c) 2000 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
/*
 * @file        service-manager-cmd.cpp
 * @author      Sebastian Grabowski (s.grabowski@samsung.com)
 * @version     1.0
 * @brief       Implementation of security-manager-cmd tool for offline mode
 */
/* vim: set ts=4 et sw=4 tw=78 : */

#include <iostream>
#include <utility>
#include <vector>
#include <map>
#include <string>

#include <dpl/log/log.h>
#include <dpl/singleton.h>
#include <protocols.h>
#include <security-manager.h>

#include <boost/program_options.hpp>
namespace po = boost::program_options;

static std::map <std::string, enum app_install_path_type> app_install_path_type_map = {
    {"rw", SECURITY_MANAGER_PATH_RW},
    {"ro", SECURITY_MANAGER_PATH_RO},
    {"public_ro", SECURITY_MANAGER_PATH_PUBLIC_RO},
    {"rw_others_ro", SECURITY_MANAGER_PATH_OWNER_RW_OTHER_RO},
    {"trusted_rw", SECURITY_MANAGER_PATH_TRUSTED_RW},
};

static std::map <std::string, enum security_manager_user_type> user_type_map = {
    {"system", SM_USER_TYPE_SYSTEM},
    {"admin", SM_USER_TYPE_ADMIN},
    {"guest", SM_USER_TYPE_GUEST},
    {"normal", SM_USER_TYPE_NORMAL},
    {"security", SM_USER_TYPE_SECURITY}
};

static std::map <std::string, enum app_install_type> install_type_map = {
    {"local", SM_APP_INSTALL_LOCAL},
    {"global", SM_APP_INSTALL_GLOBAL},
    {"preloaded", SM_APP_INSTALL_PRELOADED}
};

static po::options_description getGenericOptions()
{
    po::options_description opts("Generic options");
    opts.add_options()
         ("help,h", "produce help message")
         ("install,i", "install an application")
         ("manage-users,m", po::value<std::string>(), "add or remove user, parameter is 'a' or 'add' (for add) and 'r' or 'remove' (for remove)")
         ;
    return opts;
}

static po::options_description getInstallOptions()
{
    po::options_description opts("Install options");
    opts.add_options()
         ("app,a", po::value<std::string>()->required(),
          "application name (required)")
         ("pkg,g", po::value<std::string>()->required(),
          "package name for the application (required)")
         /*
          * multitoken: Specifies that the value can span multiple tokens.
          *             So it is possible to pass values to an option like
          *             this:
          *             --path=/home/user dirtype
          *             --path /home/user dirtype
          *             --path="/home/user" dirtype
          */
         ("path,p", po::value< std::vector<std::string> >()->multitoken(),
          "path for setting smack labels (may occur more than once).\n"
          "Format: --path <path> <path type>\n"
          "  where <path type> is: \trw, ro, public_ro, rw_others_ro, trusted_rw\n"
          "  ('trusted rw' requires author id)\n"
          "example:\n"
          "        \t--path=/home/user/app rw")
         ("privilege,s", po::value< std::vector<std::string> >(),
          "privilege for the application (may occur more than once)")
         ("uid,u", po::value<uid_t>()->required(),
          "user identifier number (required)")
         ("tizen,t", po::value<std::string>(),
          "target tizen version (e.g. 2.4, 3.0)")
         ("author-id,c", po::value<std::string>(),
          "unique author's identifier (required for trusted_rw paths)")
         ("install-type", po::value<std::string>(),
          "type of installation (local, global, preloaded)")
         ;
    return opts;
}

static po::options_description getUserOptions()
{
    po::options_description opts("User management options");
    opts.add_options()
        ("uid,u", po::value<uid_t>()->required(), "user identifier number (required)")
        ("usertype,t", po::value<std::string>(), "user type:"
                "one of system, admin, guest, normal. Set to 'normal' by default,"
                "ignored on user removal")
         ;
    return opts;
}

static po::options_description getAllOptions()
{
    po::options_description opts("Allowed options");
    opts.add(getGenericOptions());
    opts.add(getInstallOptions());
    opts.add(getUserOptions());

    return opts;
}

static void usage(std::string name)
{
    using namespace std;

    cout << endl << name << " usage:" << endl;
    cout << endl << getAllOptions() << endl << endl;
}

void parseCommandOptions(int argc, char *argv[],
                                po::options_description opts,
                                po::variables_map &vm)
{
    const po::positional_options_description p;
    /* style options:
     * unix_style: The more-or-less traditional unix style. It looks as
     *     follows: unix_style = (allow_short | short_allow_adjacent |
     *                            short_allow_next | allow_long |
     *                            long_allow_adjacent | long_allow_next |
     *                            allow_sticky | allow_guessing |
     *                            allow_dash_for_short)
     * allow_long_disguise: Allow long options with single option starting
     *     character, e.g -foo=10
     * allow_guessing: Allow abbreviated spellings for long options, if
     *     they unambiguously identify long option. No long
     *     option name should be prefix of other long option name if
     *     guessing is in effect.
     * allow_short: Alow "-<single character" style.
     * short_allow_adjacent: Allow option parameter in the same token for
     *     short options.
     * short_allow_next: Allow option parameter in the next token for
     *     short options.
     * allow_long: Allow "--long_name" style.
     * long_allow_adjacent: Allow option parameter in the same token for
     *     long option, like in --foo=10
     * long_allow_next: Allow option parameter in the next token for long
     *     options.
     * allow_sticky: Allow to merge several short options together, so
     *     that "-s -k" become "-sk". All of the options but
     *     last should accept no parameter. For example, if "-s" accept a
     *     parameter, then "k" will be taken as
     *     parameter, not another short option. Dos-style short options
     *     cannot be sticky.
     * allow_dash_for_short: Allow "-" in short options.
     */
    po::store(po::command_line_parser(argc, argv).
                  options(getGenericOptions().add(opts)).positional(p).
                  style((po::command_line_style::unix_style |
                        po::command_line_style::allow_long_disguise) &
                        ~po::command_line_style::allow_guessing).
                  run(),
              vm);
    po::notify(vm);
}

static bool loadPaths(const std::vector<std::string> &paths,
                      struct app_inst_req &req)
{
    if (paths.size() & 1) {
        std::cout << "Wrong number of tokens was given for path option." <<
                     std::endl;
        LogDebug("Wrong paths size: " << paths.size());
        return false;
    }
    req.pkgPaths.clear();
    for (std::vector<std::string>::size_type i = 1; i < paths.size(); i += 2) {
        app_install_path_type pathType;
        LogDebug("path: " << paths[i - 1]);
        try {
            pathType = app_install_path_type_map.at(paths[i]);
        } catch (const std::out_of_range &e) {
            std::cout << "Invalid path type found." << std::endl;
            LogError("Invalid path type found.");
            req.pkgPaths.clear();
            return false;
        }
        LogDebug("path type: " << pathType << " (" << paths[i] << ")");
        req.pkgPaths.push_back(std::make_pair(paths[i - 1], pathType));
    }
    return (!req.pkgPaths.empty());
}

static void parseInstallOptions(int argc, char *argv[],
                                struct app_inst_req &req,
                                po::variables_map &vm)
{

    parseCommandOptions(argc, argv, getInstallOptions(), vm);

    if (vm.count("app"))
        req.appName = vm["app"].as<std::string>();
    if (vm.count("pkg"))
        req.pkgName = vm["pkg"].as<std::string>();
    if (vm.count("path")) {
        const std::vector<std::string> paths =
            vm["path"].as<std::vector<std::string> >();
        if (!loadPaths(paths, req)) {
            po::error e("Error in parsing path arguments.");
            throw e;
        }
    }
    if (vm.count("privilege")) {
        req.privileges = vm["privilege"].as<std::vector<std::string> >();
        if (req.privileges.empty()) {
            po::error e("Error in parsing privilege arguments.");
            throw e;
        }
#ifdef BUILD_TYPE_DEBUG
        LogDebug("Passed privileges:");
        for (const auto &p : req.privileges) {
            LogDebug("    " << p);
        }
#endif
    }
    if (vm.count("uid"))
        req.uid = vm["uid"].as<uid_t>();
    if (vm.count("tizen"))
        req.tizenVersion = vm["tizen"].as<std::string>();
    if (vm.count("author-id"))
        req.authorName = vm["author-id"].as<std::string>();
    if (vm.count("install-type"))
        req.installationType = install_type_map.at(vm["install-type"].as<std::string>());

}

static void parseUserOptions(int argc, char *argv[],
                             struct user_req &req,
                             po::variables_map &vm)
{
    parseCommandOptions(argc, argv, getUserOptions(), vm);
    try {
        if (vm.count("uid"))
            req.uid = vm["uid"].as<uid_t>();
        if (vm.count("usertype")){
            req.utype = user_type_map.at(vm["usertype"].as<std::string>());
        } else
            req.utype = SM_USER_TYPE_NORMAL;
    } catch (const std::out_of_range &e) {
        po::error er("Invalid user type found.");
        throw er;
    }
}

static int installApp(const struct app_inst_req &req)
{
    int ret = EXIT_FAILURE;

    ret = security_manager_app_install(&req);
    if (SECURITY_MANAGER_SUCCESS == ret) {
        std::cout << "Application " << req.appName <<
                  " installed successfully." << std::endl;
        LogDebug("Application " << req.appName <<
                 " installed successfully.");
    } else {
        std::cout << "Failed to install " << req.appName << " application: " <<
                  security_manager_strerror(static_cast<lib_retcode>(ret)) <<
                  " (" << ret << ")." << std::endl;
        LogError("Failed to install " << req.appName << " application: " <<
                 security_manager_strerror(static_cast<lib_retcode>(ret)) <<
                 " (" << ret << ")." << std::endl);
    }
    return ret;
}

static int manageUserOperation(const struct user_req &req, std::string operation)
{
    int ret = EXIT_FAILURE;
    if (operation == "a" || operation == "add") {
        ret = security_manager_user_add(&req);
        operation = "add";
    }
    else if (operation == "r" || operation == "remove") {
        ret = security_manager_user_delete(&req);
        operation = "remove";
    } else {
        std::cout << "Manage user option requires argument:"
                "\n\t'a' or 'add' (for adding user)"
                "\n\t'r' or 'remove' (for removing user)" << std::endl;
        LogError("Manage user option wrong argument");
        return EXIT_FAILURE;
    }

    if (SECURITY_MANAGER_SUCCESS == ret) {
        std::cout << "User " << operation << " operation successfully finished (uid: "
                << req.uid << ")" << std::endl;
        LogDebug("User " << operation << " operation successfully finished (uid: "
                << req.uid << ")");
    } else {
        std::cout << "Failed to "<< operation << " user of uid " << req.uid << ". " <<
                  security_manager_strerror(static_cast<lib_retcode>(ret)) <<
                  " (" << ret << ")." << std::endl;
        LogError("Failed to "<< operation << " user of uid " << req.uid << "." <<
                 security_manager_strerror(static_cast<lib_retcode>(ret)) <<
                 " (" << ret << ").");
    }
    return ret;
}

int main(int argc, char *argv[])
{
    po::variables_map vm;

    try
    {
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER_INSTALLER");

        LogDebug("argc: " << argc);
        for (int i = 0; i < argc; ++i)
            LogDebug("argv [" << i << "]: " << argv[i]);
        if (argc < 2) {
            std::cout << "Missing arguments." << std::endl;
            usage(std::string(argv[0]));
            return EXIT_FAILURE;
        }

         po::store(po::command_line_parser(argc, argv).
                   options(getGenericOptions()).allow_unregistered().run(),
                   vm);
        if (vm.count("help")) {
            usage(std::string(argv[0]));
            return EXIT_SUCCESS;
        }
        LogDebug("Generic arguments has been parsed.");

        if (vm.count("install")) {
            struct app_inst_req *req = nullptr;
            LogDebug("Install command.");
            if (security_manager_app_inst_req_new(&req) != SECURITY_MANAGER_SUCCESS)
                return EXIT_FAILURE;
            parseInstallOptions(argc, argv, *req, vm);
            return installApp(*req);
        } else if (vm.count("manage-users")) {
            std::string operation = vm["manage-users"].as<std::string>();
            struct user_req *req = nullptr;
            LogDebug("Manage users command.");
            if (security_manager_user_req_new(&req) != SECURITY_MANAGER_SUCCESS)
                return EXIT_FAILURE;
            parseUserOptions(argc, argv, *req, vm);
            return manageUserOperation(*req, operation);
        } else {
            std::cout << "No command argument was given." << std::endl;
            usage(std::string(argv[0]));
            return EXIT_FAILURE;
        }
    }
    catch (po::error &e) {
        std::cout << e.what() << std::endl;
        LogError("Program options error occured: " << e.what());
        return EXIT_FAILURE;
    }
    catch (const std::exception &e) {
        std::cout << "Error occured: " << e.what() << std::endl;
        LogError("Error occured: " << e.what());
    }


    return EXIT_FAILURE;
}
