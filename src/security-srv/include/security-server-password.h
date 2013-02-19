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

#ifndef SECURITY_SERVER_PASSWORD_H
#define SECURITY_SERVER_PASSWORD_H

#include "security-server-common.h"
#include "security-server-comm.h"

int process_valid_pwd_request(int sockfd);
int process_set_pwd_request(int sockfd);
int process_reset_pwd_request(int sockfd);
int process_reset_pwd_request(int sockfd);
int process_chk_pwd_request(int sockfd);
int process_set_pwd_max_challenge_request(int sockfd);
int process_set_pwd_validity_request(int sockfd);
void initiate_try(void);

#endif
