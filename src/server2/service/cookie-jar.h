/*
 *  Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Bumjin Im <bj.im@samsung.com>
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
 * @file        cookie-jar.h
 * @author      Pawel Polawski (p.polawski@partner.samsung.com)
 * @version     1.0
 * @brief       This function contain header of CookieJar class which holds cookies structures
 */

#ifndef _SECURITY_SERVER_COOKIE_JAR_
#define _SECURITY_SERVER_COOKIE_JAR_

#include <stdio.h>

#include <dpl/log/log.h>
#include <dpl/exception.h>
#include <vector>
#include <stdbool.h>


namespace SecurityServer {

enum class CompareType
{
    COOKIE_ID,
    PID,
    PATH,
    SMACKLABEL,
    PERMISSIONS
};


struct Cookie
{
    std::vector<char> cookieId;     //ID key
    pid_t pid;                      //owner PID
    std::string binaryPath;         //path to owner binary
    std::string smackLabel;         //owner SMACK label
    std::vector<int> permissions;   //owner GIDs
};


class CookieJar
{
public:
    CookieJar(void);
    ~CookieJar(void);

    const Cookie * GenerateCookie(int pid);
    void DeleteCookie(const Cookie &pattern, CompareType criterion);

    const Cookie * SearchCookie(const Cookie &pattern, CompareType criterion) const;
    bool CompareCookies(const Cookie &c1, const Cookie &c2, CompareType criterion) const;

private:
    std::vector<Cookie> m_cookieList;
};


} // namespace SecurityServer
#endif // _SECURITY_SERVER_COOKIE_JAR_
