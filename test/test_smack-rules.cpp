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
 * @file       test_smack-rules.cpp
 * @author     Dariusz Michaluk (d.michaluk@samsung.com)
 * @version    1.0
 */

#include <boost/test/unit_test.hpp>
#include <fstream>
#include <vector>
#include <tuple>

#include <dpl/log/log.h>
#include <smack-rules.h>
#include <smack-labels.h>

using namespace SecurityManager;
using namespace SecurityManager::SmackLabels;

typedef std::tuple<std::string, std::string, std::string> Rule;
typedef std::vector<Rule> Rules;

struct RulesFixture
{
    RulesFixture()
    {
        if (std::ifstream(smackRulesFilePath))
            BOOST_REQUIRE_MESSAGE(unlink(smackRulesFilePath) == 0,
                                  "Error while unlink the file: " << smackRulesFilePath);
        if (std::ifstream(smackRulesBackupFilePath))
            BOOST_REQUIRE_MESSAGE(unlink(smackRulesBackupFilePath) == 0,
                                  "Error while unlink the file: " << smackRulesBackupFilePath);
        if (std::ifstream(templateRulesFilePath))
            BOOST_REQUIRE_MESSAGE(unlink(templateRulesFilePath) == 0,
                                  "Error while unlink the file: " << templateRulesFilePath);
    }

    ~RulesFixture()
    {
        if (std::ifstream(smackRulesFilePath))
            BOOST_WARN_MESSAGE(unlink(smackRulesFilePath) == 0,
                               "Error while unlink the file: " << smackRulesFilePath);
        if (std::ifstream(smackRulesBackupFilePath))
            BOOST_WARN_MESSAGE(unlink(smackRulesBackupFilePath) == 0,
                               "Error while unlink the file: " << smackRulesBackupFilePath);
        if (std::ifstream(templateRulesFilePath))
            BOOST_WARN_MESSAGE(unlink(templateRulesFilePath) == 0,
                               "Error while unlink the file: " << templateRulesFilePath);
    }

    const static char* smackRulesFilePath;
    const static char* smackRulesBackupFilePath;
    const static char* templateRulesFilePath;
    const static Rules rules;
};

const char* RulesFixture::smackRulesFilePath = "/tmp/SecurityManagerUTSmackRules.rules";
const char* RulesFixture::smackRulesBackupFilePath = "/tmp/SecurityManagerUTSmackRulesBackup.rules";
const char* RulesFixture::templateRulesFilePath = "/tmp/SecurityManagerUTTemplateRules.rules";

const Rules RulesFixture::rules = { Rule("music-player", "audio", "rwxa--"),
                                    Rule("email", "gallery", "rwxat-"),
                                    Rule("maps", "gps", "r-x--l"),
                                    Rule("browser", "camera", "-wx---"),
                                    Rule("message", "nfc", "-----l") };

BOOST_AUTO_TEST_SUITE(SMACK_RULES_TEST)

BOOST_FIXTURE_TEST_CASE(T1100_add_save_load_smack_rules, RulesFixture)
{
    SmackRules smackRules, smackRulesBackup;
    std::ifstream smackRulesFile, smackRulesBackupFile;
    std::string smackRuleFromFile, smackRuleFromBackupFile, smackRuleOriginal;

    for (auto r : rules)
        BOOST_REQUIRE_NO_THROW(smackRules.add(std::get<0>(r), std::get<1>(r), std::get<2>(r)));

    BOOST_REQUIRE_NO_THROW(smackRules.saveToFile(smackRulesFilePath));
    BOOST_REQUIRE_NO_THROW(smackRulesBackup.loadFromFile(smackRulesFilePath));
    BOOST_REQUIRE_NO_THROW(smackRulesBackup.saveToFile(smackRulesBackupFilePath));

    smackRulesFile.open(smackRulesFilePath);
    smackRulesBackupFile.open(smackRulesBackupFilePath);

    for (auto r : rules) {
        std::getline(smackRulesFile, smackRuleFromFile);
        std::getline(smackRulesBackupFile, smackRuleFromBackupFile);

        smackRuleOriginal = std::get<0>(r) + " " + std::get<1>(r) + " " + std::get<2>(r);

        BOOST_REQUIRE(smackRuleFromFile == smackRuleOriginal);
        BOOST_REQUIRE(smackRuleFromFile == smackRuleFromBackupFile);
    }

    smackRulesFile.close();
    smackRulesBackupFile.close();
}

BOOST_FIXTURE_TEST_CASE(T1110_add_modify_save_smack_rules, RulesFixture)
{
    SmackRules smackRules;
    std::ifstream smackRulesFile;
    std::string smackRuleFromFile, smackRuleModify;

    for (auto r : rules) {
        BOOST_REQUIRE_NO_THROW(smackRules.add(std::get<0>(r), std::get<1>(r), std::get<2>(r)));
        BOOST_REQUIRE_NO_THROW(smackRules.addModify(std::get<0>(r), std::get<1>(r), "xatl", ""));
        BOOST_REQUIRE_NO_THROW(smackRules.addModify(std::get<0>(r), std::get<1>(r), "", "tl"));
    }

    BOOST_REQUIRE_NO_THROW(smackRules.saveToFile(smackRulesFilePath));
    smackRulesFile.open(smackRulesFilePath);

    for (auto r : rules) {
        std::getline(smackRulesFile, smackRuleFromFile);

        smackRuleModify = std::get<0>(r) + " " + std::get<1>(r) + " " + std::get<2>(r).substr(0, 2) + "xa--";

        BOOST_REQUIRE(smackRuleFromFile == smackRuleModify);
    }

    smackRulesFile.close();
}

BOOST_AUTO_TEST_CASE(T1120_smack_rules_exception)
{
    SmackRules smackRules;

    BOOST_REQUIRE_THROW(smackRules.add("subject", "object", "invalidPermission"),
                        SmackException::LibsmackError);
    BOOST_REQUIRE_THROW(smackRules.add("subject", "", "rwxatl"), SmackException::LibsmackError);
    BOOST_REQUIRE_THROW(smackRules.add("", "object", "rwxatl"), SmackException::LibsmackError);

    BOOST_REQUIRE_NO_THROW(smackRules.add("subject", "object", "rwxat"));

    BOOST_REQUIRE_THROW(smackRules.addModify("subject", "object", "invalidPermission", ""),
                        SmackException::LibsmackError);
    BOOST_REQUIRE_THROW(smackRules.addModify("subject", "object", "", "invalidPermission"),
                        SmackException::LibsmackError);
    BOOST_REQUIRE_THROW(smackRules.addModify("subject", "", "rw", "xt"),
                        SmackException::LibsmackError);
    BOOST_REQUIRE_THROW(smackRules.addModify("", "object", "rw", "xt"),
                        SmackException::LibsmackError);

    const std::string noExistingFilePath = "/tmp/SecurityManagerUTNoExistingFile";
    BOOST_REQUIRE_THROW(smackRules.loadFromFile(noExistingFilePath), SmackException::FileError);
}

BOOST_FIXTURE_TEST_CASE(T1130_smack_rules_templates, RulesFixture)
{
    SmackRules::RuleVector templateRules = { "System ~PROCESS~ rwxat",
                                             "~PROCESS~ System wx",
                                             "~PROCESS~ ~PATH_RW~ rwxat",
                                             "~PROCESS~ ~PATH_RO~ rxl",
                                             "~PROCESS~ ~PATH_SHARED_RO~ rwxat",
                                             "~PROCESS~ ~PATH_TRUSTED~ rwxat" };

    std::ofstream templateRulesFile;
    templateRulesFile.open(templateRulesFilePath);
    for (auto templateRule : templateRules)
        templateRulesFile << templateRule << std::endl;
    templateRulesFile.close();

    SmackRules::RuleVector expectedRules = { "System User::Pkg::pkgNameT1130 rwxat-",
                                             "User::Pkg::pkgNameT1130 System -wx---",
                                             "User::Pkg::pkgNameT1130 User::Pkg::pkgNameT1130 rwxat-",
                                             "User::Pkg::pkgNameT1130 User::Pkg::pkgNameT1130::RO r-x--l",
                                             "User::Pkg::pkgNameT1130 User::Pkg::pkgNameT1130::SharedRO rwxat-",
                                             "User::Pkg::pkgNameT1130 User::Author::5000 rwxat-" };

    const std::string appName = "appNameT1130";
    const std::string pkgName = "pkgNameT1130";
    const std::string appProcessLabel = generateProcessLabel(appName, pkgName, false);
    const int authorId = 5000;
    SmackRules smackRulesFromTemplate, smackRulesFromFileTemplate;

    BOOST_REQUIRE_NO_THROW(smackRulesFromTemplate.addFromTemplate(templateRules,
                                                                  appProcessLabel,
                                                                  pkgName,
                                                                  authorId));

    BOOST_REQUIRE_NO_THROW(smackRulesFromTemplate.saveToFile(smackRulesFilePath));

    const std::string noExistingFilePath = "/tmp/SecurityManagerUTNoExistingFile";
    BOOST_REQUIRE_THROW(smackRulesFromFileTemplate.addFromTemplateFile(noExistingFilePath,
                                                                       appProcessLabel,
                                                                       pkgName,
                                                                       authorId),
                                                                       SmackException::FileError);

    BOOST_REQUIRE_NO_THROW(smackRulesFromFileTemplate.addFromTemplateFile(templateRulesFilePath,
                                                                          appProcessLabel,
                                                                          pkgName,
                                                                          authorId));

    BOOST_REQUIRE_NO_THROW(smackRulesFromFileTemplate.saveToFile(smackRulesBackupFilePath));

    std::ifstream smackRulesFile, smackRulesBackupFile;
    std::string smackRuleFromFile, smackRuleFromBackupFile;
    smackRulesFile.open(smackRulesFilePath);
    smackRulesBackupFile.open(smackRulesBackupFilePath);

    for (auto expectedRule : expectedRules) {
        std::getline(smackRulesFile, smackRuleFromFile);
        std::getline(smackRulesBackupFile, smackRuleFromBackupFile);

        BOOST_REQUIRE(smackRuleFromFile == expectedRule);
        BOOST_REQUIRE(smackRuleFromBackupFile == expectedRule);
    }

    smackRulesFile.close();
    smackRulesBackupFile.close();
}

BOOST_AUTO_TEST_SUITE_END()
