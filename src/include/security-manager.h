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
 *
 *	Security Manager library header
 */
/*
 * @file        security-manager.h
 * @author      Pawel Polawski (p.polawski@samsung.com)
 * @version     1.0
 * @brief       This file contains header of security-manager API
 */

#ifndef SECURITY_MANAGER_H_
#define SECURITY_MANAGER_H_

#include <sys/types.h>

#include "app-manager.h"
#include "app-runtime.h"
#include "app-sharing.h"
#include "user-manager.h"
#include "policy-manager.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * This function translates lib_retcode error codes to strings describing
 * errors.
 * @param[in] rc error code of lib_retcode type
 * @return string describing error for error code
 */
const char *security_manager_strerror(enum lib_retcode rc);

#ifdef __cplusplus
}
#endif

#endif /* SECURITY_MANAGER_H_ */
