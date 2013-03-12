/*
 * Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */
#include <dpl/assert.h>
#include <dpl/log/log.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>
#include <malloc.h>
#include <sys/stat.h>
#include <ace/ConfigurationManager.h>

using namespace std;

namespace {
const string currentXMLSchema("bondixml.xsd");
}

ConfigurationManager * ConfigurationManager::instance = NULL;


string ConfigurationManager::getCurrentPolicyFile(void) const
{
    LogError("ConfigurationManager::getCurrentPolicyFile is DEPRECATED");
    return "";
}

string ConfigurationManager::getFullPathToCurrentPolicyFile(void) const
{
    LogError("ConfigurationManager::getFullPathToCurrentPolicyFile"
             "is DEPRECATED");
    return "";
}

string ConfigurationManager::getFullPathToCurrentPolicyXMLSchema(void) const
{
    LogError("ConfigurationManager::getFullPathToCurrentPolicyXMLSchema"
             "is DEPRECATED");
    return "";
}

int ConfigurationManager::addPolicyFile(const string &)
{
    LogError("ConfigurationManager::addPolicyFile is DEPRECATED");
    return CM_GENERAL_ERROR;
}

int ConfigurationManager::removePolicyFile(const string&)
{
    LogError("ConfigurationManager::removePolicyFile is DEPRECATED");
    return CM_GENERAL_ERROR;
}

int ConfigurationManager::changeCurrentPolicyFile(const string&)
{
    LogError("ConfigurationManager::changeCurrentPolicyFile is DEPRECATED");
    return CM_GENERAL_ERROR;
}

string ConfigurationManager::extractFilename(const string&) const
{
    LogError("ConfigurationManager::extractFilename is DEPRECATED");
    return "";
}


int ConfigurationManager::parse(const string&)
{
    LogError("ConfigurationManager::parse is DEPRECATED");
    return CM_GENERAL_ERROR;
}

bool ConfigurationManager::copyFile(FILE*, FILE*, int) const
{
    LogError("ConfigurationManager::copyFile is DEPRECATED");
    return false;
}

bool ConfigurationManager::checkIfFileExistst(const string&) const
{
    LogError("ConfigurationManager::checkIfFileExistst is DEPRECATED");
    return false;
}

const list<string> & ConfigurationManager::getPolicyFiles() const
{
    LogError("ConfigurationManager::getPolicyFiles is DEPRECATED");
    static list<string> aList;
    return aList;
}

const string & ConfigurationManager::getConfigFile() const
{
    LogError("ConfigurationManager::getConfigFile is DEPRECATED");
    static string returnString("");
    return returnString;
}

string ConfigurationManager::getFullPathToPolicyFile(PolicyType policy) const
{
    string storagePath = getStoragePath();
    string fileName;

    switch (policy) {
    case PolicyType::WAC2_0: {
        fileName = ACE_WAC_POLICY_FILE_NAME;
        break; }
    case PolicyType::Tizen: {
        fileName = ACE_TIZEN_POLICY_FILE_NAME;
        break; }
    default: {
        LogError("Invalid policy file requested");
        return ""; }
    }

    return storagePath + fileName;
}

string ConfigurationManager::getFullPathToPolicyXMLSchema() const
{
    string storagePath = getStoragePath();
    if (*(storagePath.rbegin()) == '/')
    {
        return storagePath + currentXMLSchema;
    }
    return storagePath + "/" + currentXMLSchema;
}

string ConfigurationManager::getStoragePath(void) const
{
    return ACE_MAIN_STORAGE;
}
