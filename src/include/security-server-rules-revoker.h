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
#ifndef _SECURITY_SERVER_RULES_REVOKER_H_
#define _SECURITY_SERVER_RULES_REVOKER_H_

#include <linux/cn_proc.h>

void rules_revoker_init(void);
int rules_revoker_add(int pid, const char *subject, const char *object);
void rules_revoker_callback(const struct proc_event *event);

#endif // _SECURITY_SERVER_RULES_REVOKER_H_

