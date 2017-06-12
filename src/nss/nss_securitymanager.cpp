/*
 *  Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 *  Security Manager NSS library
 */
/*
 * @file        nss_securitymanager.cpp
 * @author      Aleksander Zdyb <a.zdyb@samsung.com>
 * @version     1.0
 * @brief       This file contains NSS library implementation for Security Manager
 */

#include <cerrno>
#include <cstddef>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <nss.h>
#include <unistd.h>
#include <cstdlib>

#include <vector>

#include <security-manager.h>

namespace {

size_t getBufferSize()
{
    size_t max = 4096, tmp;
    max = max < (tmp = sysconf(_SC_GETPW_R_SIZE_MAX)) ? tmp : max;
    return max < (tmp = sysconf(_SC_GETGR_R_SIZE_MAX)) ? tmp : max;
}

} // anonymous namespace

extern "C" {


__attribute__((visibility("default")))
enum nss_status _nss_securitymanager_initgroups_dyn(const char *user, gid_t group_gid, long int *start,
                                                    long int *size, gid_t **groupsp,
                                                    long int limit, int *errnop)
{
    try {
        (void) group_gid;

        int ret;
        const static size_t BUFFER_SIZE = getBufferSize();
        const static size_t MEMORY_LIMIT = BUFFER_SIZE << 3;
        std::vector<char> buffer(BUFFER_SIZE);
        passwd pwnambuffer;
        passwd *pwnam = NULL;

        while (ERANGE == (ret = TEMP_FAILURE_RETRY(getpwnam_r(user, &pwnambuffer, buffer.data(), buffer.size(), &pwnam)))
               && buffer.size() < MEMORY_LIMIT)
        {
            buffer.resize(buffer.size() << 1);
        }

        if (ret == ERANGE) {
            *errnop = ENOMEM;
            return NSS_STATUS_UNAVAIL;
        }

        if (ret || pwnam == NULL) {
            *errnop = ENOENT;
            return NSS_STATUS_NOTFOUND;
        }

        char **groups;
        size_t groupsCount;
        ret = security_manager_groups_get_for_user(pwnam->pw_uid, &groups, &groupsCount);

        if (ret == SECURITY_MANAGER_ERROR_NO_SUCH_OBJECT) {
            // If user is not managed by Security Manager, we want to apply all the groups
            ret = security_manager_groups_get(&groups, &groupsCount);
        }

        if (ret == SECURITY_MANAGER_ERROR_MEMORY) {
            *errnop = ENOMEM;
            return NSS_STATUS_UNAVAIL;
        }

        if (ret == SECURITY_MANAGER_ERROR_ACCESS_DENIED) {
            *errnop = EPERM;
            return NSS_STATUS_UNAVAIL;
        }

        if (ret != SECURITY_MANAGER_SUCCESS) {
            *errnop = ENOENT;
            return NSS_STATUS_UNAVAIL;
        }

        std::vector<gid_t> result;

        for (size_t i = 0; i < groupsCount; ++i) {
            group *grnam = NULL;
            group groupbuff;

            while (ERANGE == (ret = TEMP_FAILURE_RETRY(getgrnam_r(groups[i], &groupbuff, buffer.data(), buffer.size(), &grnam)))
                   && buffer.size() < MEMORY_LIMIT)
            {
                buffer.resize(buffer.size() << 1);
            }

            if (ret == ERANGE) {
                *errnop = ENOMEM;
                return NSS_STATUS_UNAVAIL;
            }

            if (grnam)
                result.push_back(grnam->gr_gid);
        }

        if (((*size) - (*start)) < static_cast<long int>(result.size())) {
            long int required = (*start) + result.size();
            // value bigger is the lowest power of 2 that is bigger than required value
            long int bigger = 1 << ((sizeof(unsigned long) << 3) - __builtin_clzl(static_cast<unsigned long>(required)));

            gid_t *ptr = static_cast<gid_t*>(realloc(*groupsp, sizeof(gid_t) * (bigger)));
            if (!ptr) {
                *errnop = ENOMEM;
                return NSS_STATUS_UNAVAIL;
            }
            *size = bigger;
            *groupsp = ptr;
        }

        for (auto e : result) {
            (*groupsp)[(*start)++] = e;
            if (limit > 0 && (*start) >= limit)
                break;
        }

    } catch (...) {
        // We are leaving c++ code and going to pure c so this
        // Pokemon catch (catch them all) is realy required here.
        return NSS_STATUS_UNAVAIL;
    }
    return NSS_STATUS_SUCCESS;
}

} /* extern "C" */
