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
//
//
//
//  @ Project : Access Control Engine
//  @ File Name : parser.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#ifndef _PARSER_H_
#define _PARSER_H_

//#include "/usr/include/libxml2/libxml/parser.h"
#include <string>
#include <libxml/xmlreader.h>
#include <libxml/c14n.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include "Policy.h"
#include "PolicySet.h"
#include "Request.h"
#include "Rule.h"
#include "Attribute.h"
#include "TreeNode.h"
#include "Subject.h"
#include "Condition.h"
#include "Effect.h"

#define whitespaces " \n\t\r"

enum CanonicalizationAlgorithm
{
    C14N,
    C14NEXCLUSIVE
};

class Parser
{
  private:
    RuleId ruleId;
    xmlTextReaderPtr reader;

    TreeNode * root;
    TreeNode * currentRoot;
    Subject * currentSubject;
    Condition * currentCondition;
    Attribute * currentAttribute;
    std::string * currentText;

    bool processingSignature;
    bool canonicalizeOnce;

    void processNode(xmlTextReaderPtr reader);

    //Node Handlers
    void endNodeHandler(xmlTextReaderPtr reader);
    void textNodeHandler(xmlTextReaderPtr reader);
    void startNodeHandler(xmlTextReaderPtr reader);

    //Node names handlers
    void handleAttr(xmlTextReaderPtr reader);
    void handleRule(xmlTextReaderPtr reader);
    void handleSubject();
    void handleCondition(xmlTextReaderPtr reader);
    void handleSubjectMatch(xmlTextReaderPtr reader);
    void handleMatch(xmlTextReaderPtr reader,
            Attribute::Type);
    void handlePolicy(xmlTextReaderPtr reader,
            TreeNode::TypeID type);

    //helpers
    Policy::CombineAlgorithm convertToCombineAlgorithm(xmlChar*);
    ExtendedEffect convertToEffect(xmlChar *effect);
    Attribute::Match convertToMatchFunction(xmlChar * func);
    void consumeCurrentText();
    void consumeCurrentAttribute();
    void consumeSubjectMatch(xmlChar * value = NULL);
    void consumeCurrentSubject();
    void consumeCurrentCondition();
    void trim(std::string *);
    // KW     void canonicalize(const char *, const char *, CanonicalizationAlgorithm canonicalizationAlgorithm);
    // KW     int extractNodeToFile(xmlTextReaderPtr reader, const char * filename);

    static const char *TOKEN_PARAM;
  public:
    Parser();
    ~Parser();
    TreeNode * parse(const std::string& filename, const std::string& schema);
};

#endif  //_PARSER_H
