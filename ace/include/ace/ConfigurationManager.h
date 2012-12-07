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
#ifndef _CONFIGURATIONMANAGER_H_
#define _CONFIGURATIONMANAGER_H_

#include <list>
#include <string.h>
#include <string>
#include "Constants.h"
#include <iostream>
#include <dpl/log/log.h>

enum class PolicyType {
    WAC2_0,
    Tizen
};

#define POLICY_NAME_WAC2_0                  "WAC2.0"
#define POLICY_NAME_TIZEN                   "Tizen"
#define POLICY_WIDGET_TYPE_ATTRIBUTE_NAME   "WrtSecurity.WidgetPolicyType"

#pragma message "ATTR_ACTIVE_POLICY BAD_CAST, PARSER_ERROR, PARSER_SUCCESS\
 macros are DEPRECATED"
#define ATTR_ACTIVE_POLICY BAD_CAST("active") // !! DEPRECATED !!
#define PARSER_ERROR     1 // !! DEPRECATED !!
#define PARSER_SUCCESS   0 // !! DEPRECATED !!

class ConfigurationManager
{
  public:
    // !! DEPRECATED !!
    enum ConfigurationManagerResult
    {
        CM_OPERATION_SUCCESS = 0,
        CM_GENERAL_ERROR = -1,
        CM_FILE_EXISTS = -2,
        CM_REMOVE_ERROR = -3,
        CM_REMOVE_CURRENT = -4,
        CM_REMOVE_NOT_EXISTING = -5
    };

    // !! DEPRECATED !!
    std::string getCurrentPolicyFile(void) const;
    std::string getFullPathToCurrentPolicyFile(void) const;
    std::string getFullPathToCurrentPolicyXMLSchema(void) const;
    int addPolicyFile(const std::string & filePath);
    int removePolicyFile(const std::string& fileName);
    int changeCurrentPolicyFile(const std::string& filePath);
    std::string extractFilename(const std::string& path) const;

    /**
     * ACE policy file path getter
     * @return Full path to policy file
     */
    std::string getFullPathToPolicyFile(PolicyType policy) const;

    /**
     * ACE policy dtd file path getter
     * @return Full path to ACE current policy file
     */
    std::string getFullPathToPolicyXMLSchema(void) const;

    /**
     * ACE policy storage path getter
     * @return Full path to ACE policy file storage
     */
    std::string getStoragePath(void) const;

    /**
     * Method to obtain instance of configuration manager
     * @return retuns pointer to configuration manager or NULL in case of error
     */
    static ConfigurationManager * getInstance()
    {
        if (!instance) {
            instance = new ConfigurationManager();
        }
        return instance;
    }

  protected:

    // !! DEPRECATED !!
    int parse(const std::string&);
    bool copyFile(FILE*, FILE*, int lenght = 1024) const;
    bool checkIfFileExistst(const std::string&) const;
    const std::list<std::string> & getPolicyFiles() const;
    const std::string & getConfigFile() const;

    ConfigurationManager()
    {
    }
    virtual ~ConfigurationManager()
    {
    }

private:

    static ConfigurationManager * instance;
};

#endif

