/*
 *  security-server
 *
 *  Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
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
 *
 */

#ifndef SECURITY_SERVER_COOKIE_H
#define SECURITY_SERVER_COOKIE_H

#include "security-server-common.h"

int free_cookie_item(cookie_list *cookie);
cookie_list *delete_cookie_item(cookie_list *cookie);
cookie_list *search_existing_cookie(int pid, const cookie_list *c_list);
cookie_list *search_cookie(const cookie_list *c_list, const unsigned char *cookie, int privilege);
cookie_list *search_cookie_new(const cookie_list *c_list,
                               const unsigned char *cookie,
                               const char *object,
                               const char *access_rights);
int generate_random_cookie(unsigned char *cookie, int size);
cookie_list *create_cookie_item(int pid, int sockfd, cookie_list *c_list);
cookie_list *create_default_cookie(void);
cookie_list * garbage_collection(cookie_list *cookie);
cookie_list *search_cookie_from_pid(cookie_list *c_list, int pid);
void printhex(const unsigned char *data, int size);

#endif
