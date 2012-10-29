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
/*
 * This file contain consts for Signing Template and Policy Manager
 * This values will be used to specified and identified algorithms in xml policy documents.
 * Its consistent with BONDI 1.0 released requirements
 *
 * NOTE: This values should be verified when ACF will be updated to the latest version of BONDI requirements
 * This values comes from widget digital signature 1.0 - required version of this doc is very important
 *
 **/

#ifndef ACF_CONSTS_TYPES_H
#define ACF_CONSTS_TYPES_H

//Digest Algorithms
extern const char* DIGEST_ALG_SHA256;

//Canonicalization Algorithms
extern const char* CANONICAL_ALG_C14N;

//Signature Algorithms
extern const char* SIGNATURE_ALG_RSA_with_SHA256;
extern const char* SIGNATURE_ALG_DSA_with_SHA1;
extern const char* SIGNATURE_ALG_ECDSA_with_SHA256;

#endif

