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
#include <memory>
#include <functional>
#include <string.h>
#include <stdarg.h>
#include <dpl/log/log.h>

#include <ace/parser.h>
#include <string.h>

namespace {

class ParserWarningLogger
{
  public:
    void operator()(const std::string& logMsg)
    {
        LogWarning(logMsg);
    }
};

class ParserErrorLogger
{
  public:
    void operator()(const std::string& logMsg)
    {
        LogError(logMsg);
    }
};

template <class Logger>
void xmlLogFunction(void* /*ctx*/, const char *msg, ...)
{
    const int BUFFER_SIZE = 1024;
    char buffer[BUFFER_SIZE];
    buffer[BUFFER_SIZE - 1] = '\0';
    Logger l;

    va_list va;
    va_start(va, msg);
    vsnprintf(buffer, BUFFER_SIZE - 1, msg, va);
    va_end(va);

    std::string logmsg(buffer);
    l(logmsg);
}

}

const char *Parser::TOKEN_PARAM = "param:";

Parser::Parser() :
    ruleId(0),
    reader(NULL),
    root(NULL),
    currentRoot(NULL),
    currentSubject(NULL),
    currentCondition(NULL),
    currentAttribute(NULL),
    currentText(NULL),
    processingSignature(false),
    canonicalizeOnce(false)
{
    processingSignature = true;
    canonicalizeOnce = true;
}

Parser::~Parser()
{
    /* parse function destroys reader */
    //  free(this->xmlFilename);
}

TreeNode* Parser::parse(const std::string& filename, const std::string& schema)
{
    if(root != NULL) {
        root->releaseResources();
        root = NULL;
    }

    LogDebug("Parser: opening file " << filename);

    xmlDocPtr xmlDocument = xmlParseFile(filename.c_str());
    if (!xmlDocument) {
        LogError("Couldn't parse file " << filename);
        return root;
    }

    std::unique_ptr <xmlDoc, std::function<void(xmlDoc*)> >
        doc(xmlDocument, xmlFreeDoc);

    xmlSchemaParserCtxtPtr xmlSchemaParserContext =
        xmlSchemaNewParserCtxt(schema.c_str());

    if (!xmlSchemaParserContext) {
        LogError("Couldn't load xml schema: " << schema);
        return root;
    }

    std::unique_ptr <
                     xmlSchemaParserCtxt,
                     std::function<void(xmlSchemaParserCtxt*)> >
                     schemaContext(
                                   xmlSchemaParserContext,
                                   xmlSchemaFreeParserCtxt);

    LogDebug("Setting callbacks");

    xmlSchemaSetParserErrors(
        schemaContext.get(),
        static_cast<xmlValidityErrorFunc>
            (&xmlLogFunction<ParserErrorLogger>),
        static_cast<xmlValidityWarningFunc>
            (&xmlLogFunction<ParserWarningLogger>),
        NULL);

    xmlSchemaPtr xmlSchema = xmlSchemaParse(schemaContext.get());

    if (!xmlSchema) {
        LogError("Couldn't parse xml schema: " << xmlSchema);
        return root;
    }

    xmlSchemaValidCtxtPtr xmlValidContext = xmlSchemaNewValidCtxt(xmlSchema);

    if (!xmlValidContext) {
        LogError("Couldn't create validation context!");
        return root;
    }

    std::unique_ptr <
                     xmlSchemaValidCtxt,
                     std::function<void(xmlSchemaValidCtxt*)> >
                     schemaValidContext(
                                        xmlValidContext,
                                        xmlSchemaFreeValidCtxt);

    xmlSchemaSetValidErrors(
        schemaValidContext.get(),
        static_cast<xmlValidityErrorFunc>
            (&xmlLogFunction<ParserErrorLogger>),
        static_cast<xmlValidityWarningFunc>
            (&xmlLogFunction<ParserWarningLogger>),
        NULL);

    xmlSchemaSetValidOptions(
                             schemaValidContext.get(),
                             XML_SCHEMA_VAL_VC_I_CREATE);

    bool result =
        (xmlSchemaValidateDoc(
                              schemaValidContext.get(),
                              xmlDocument) == 0 ? true : false);

    if (!result) {
        LogError("Couldn't validate policy file: " << filename <<
                 " against xml schema: " << schema);

        return root;
    }

    LogInfo("Policy file: " << filename << " validated!");

    xmlTextReaderPtr xmlReader = xmlReaderWalker(xmlDocument);

    //[CR] consider using ASSERT/DASSERT
    if (NULL == xmlReader) {
        LogError("Error, xml reader cannot be created. Probably xml file is missing (opening file " << filename << ")");
        return root;
    }

    std::unique_ptr <xmlTextReader, std::function<void(xmlTextReader*)> >
         reader(xmlReader, xmlFreeTextReader);

    int ret;
    ret = xmlTextReaderRead(reader.get());
    while (ret == 1) {
        std::unique_ptr<xmlChar, std::function<void(xmlChar*)> >
            name(xmlTextReaderName(reader.get()), xmlFree);

        if (!strcmp("policy-set", (const char *)name.get())) {
            processingSignature = false;
        } else if (!strcmp("SignedInfo",
                           (const char *)name.get()) && canonicalizeOnce) {
            #if 0 //TODO I think we don't need canonicalization in ACE only in PM,
            //we have to  verify it tough
            extractNodeToFile(reader, "output.xml");
            //TODO we should be able to handle more than one canonicalization algorithm
            canonicalize("output.xml", "canon.xml", Canonicalization::C14N);
            canonicalizeOnce = false;
            #endif
        }
        //Do not process signature of xml file
        if(!processingSignature) {
            processNode(reader.get());
        }
        ret = xmlTextReaderRead(reader.get());
    }

    if (ret != 0) {
        LogError("Error while parsing XML file");
        if (root) {
            root->releaseResources();
            root = NULL;
        }
    }

    return root;
}

void Parser::processNode(xmlTextReaderPtr reader)
{
    //TODO this is interesting, xmlTextReaderNodeType returns int but I am pretty sure
    //those integers coresponds to xmlReaderTypes
    xmlReaderTypes type =
        static_cast<xmlReaderTypes>(xmlTextReaderNodeType(reader));

    switch (type) {
    //Start element
    case XML_READER_TYPE_ELEMENT:
        startNodeHandler(reader);
        break;
    //End element
    case XML_READER_TYPE_END_ELEMENT:
        endNodeHandler(reader);
        break;
    //Text element
    case XML_READER_TYPE_TEXT:
        textNodeHandler(reader);
        break;
    default:
        //Do not handle other xml tags
        break;
    }
}

void Parser::startNodeHandler(xmlTextReaderPtr reader)
{
    xmlChar *name = xmlTextReaderName(reader);

    switch (*name) {
    case 'p':     //policy and policy-set
        if (*(name + 6) == 0) {
            handlePolicy(reader, TreeNode::Policy);
        } else {
            handlePolicy(reader, TreeNode::PolicySet);
        }
        break;
    case 'r':     //rule and resource-match
        if (*(name + 1) == 'u') {
            handleRule(reader);
        } else if (*(name + 9) == 'm') {
            handleMatch(reader, Attribute::Type::Resource);
        } else {
            handleAttr(reader);
        }
        break;
    case 's':     //subject and subject-match
        if (*(name + 7) == 0) {
            handleSubject();
        } else if (*(name + 8) == 'm') { //subject match
            handleSubjectMatch(reader);
        } else {  //subject attr
            handleAttr(reader);
        }
        break;
    case 'c':    //condition
        handleCondition(reader);
        break;
    case 'e':    //environment-match
        if (*(name + 12) == 'm') {
            handleMatch(reader, Attribute::Type::Environment);
        } else {  //env-attr
            handleAttr(reader);
        }
        break;
    }
    xmlFree(name);
}

void Parser::endNodeHandler(xmlTextReaderPtr reader)
{
    xmlChar *name = xmlTextReaderName(reader);

    switch (*name) {
    case 'p':     //policy and policy-set
        //Restore old root
        currentRoot = currentRoot->getParent();
        break;
    case 'r':     //Rule and resource match
        if (*(name + 1) == 'u') { //Rule
            currentRoot = currentRoot->getParent();
        } else {  //Resource-match
            consumeCurrentText();     //consume text if any available
            consumeCurrentAttribute();     //consume attribute
        }
        break;
    case 's':     //subject and subject-match
        if (*(name + 7) == 0) { //handle subject
            consumeCurrentSubject();
        } else if (*(name + 8) == 'm') { //handle subject match
            consumeCurrentText();
            consumeSubjectMatch();
        }
        //Subject-match end doesn't require handling
        break;
    case 'c':    //condition
        consumeCurrentCondition();
        break;
    case 'e':    //environment-match
        consumeCurrentText();     //consume text if any available
        consumeCurrentAttribute();     //consume attribute
        break;
    }
    xmlFree(name);
}

void Parser::textNodeHandler(xmlTextReaderPtr reader)
{
    delete currentText;
    xmlChar * text = xmlTextReaderValue(reader);
    Assert(text != NULL && "Parser couldn't parse PCDATA");

    currentText = new std::string(reinterpret_cast<const char * >(text));
    trim(currentText);
    xmlFree(text);
}

void Parser::handlePolicy(xmlTextReaderPtr reader,
        TreeNode::TypeID type)
{
    Policy::CombineAlgorithm algorithm;

    //Get first attribute
    xmlChar * combAlg = xmlTextReaderGetAttribute(reader, BAD_CAST("combine"));

    Assert(combAlg != NULL && "Parser error while getting attributes");
    algorithm = convertToCombineAlgorithm(combAlg);

    //Create TreeNode element
    Policy * policy = NULL;
    if (type == TreeNode::Policy) {
        policy = new Policy();
    } else {
        policy = new PolicySet();
    }
    policy->setCombineAlgorithm(algorithm);
    TreeNode * node = new TreeNode(currentRoot, type, policy);
    //Add new tree node to current's root children set
    if (currentRoot != NULL) {
        currentRoot->addChild(node);
    }

    //Switch the current root to the new node
    if (!xmlTextReaderIsEmptyElement(reader)) {
        //Current root switching is necessary only if tag is not empty
        currentRoot = node;
    }
    if (root == NULL) {
        root = currentRoot;
    }

    if (NULL == currentRoot) {
        node->releaseResources();
    }

    xmlFree(combAlg);
}

void Parser::handleRule(xmlTextReaderPtr reader)
{
    ExtendedEffect effect(Inapplicable);

    //[CR] create macros for attribute names
    xmlChar * eff = xmlTextReaderGetAttribute(reader, BAD_CAST("effect")); //get the rule attribute

    Assert(eff != NULL && "Parser error while getting attributes");
    effect = convertToEffect(eff);

    Rule * rule = NULL;
    rule = new Rule();
    rule->setEffect(effect);

    TreeNode * node = new TreeNode(currentRoot, TreeNode::Rule, rule);
    //Add new tree node to current's root children set
    if (currentRoot != NULL) { //
        currentRoot->addChild(node);
    }

    if (!xmlTextReaderIsEmptyElement(reader)) {
        currentRoot = node;
    }

    if (NULL == currentRoot) {
        node->releaseResources();
    }

    xmlFree(eff);
}

void Parser::handleSubject()
{
    currentSubject = new Subject();
    //TODO what about empty subject tag
}

void Parser::handleCondition(xmlTextReaderPtr reader)
{
    Condition::CombineType combineType = Condition::AND;

    xmlChar * combine = xmlTextReaderGetAttribute(reader, BAD_CAST("combine")); //get the rule attribute

    Assert(combine != NULL && "Parser error while getting attributes");

    combineType = *combine == 'a' ? Condition::AND : Condition::OR;

    Condition * condition = new Condition();
    condition->setCombineType(combineType);
    condition->setParent(currentCondition);

    currentCondition = condition;
    //TODO what about empty condition tag?
}

//Subject match is handled differently than resource or environment match
//Because it cannot have any children tags and can only include PCDATA
void Parser::handleSubjectMatch(xmlTextReaderPtr reader)
{
    //processing Subject
    int attributes = xmlTextReaderAttributeCount(reader);

    xmlChar * func = NULL;
    xmlChar * value = NULL;
    xmlChar * attrName = xmlTextReaderGetAttribute(reader, BAD_CAST("attr")); //get the first attribute

    if (attributes == 2) {
        //match attribute ommited, text value will be used
        func = xmlTextReaderGetAttribute(reader, BAD_CAST("func"));
    } else if (attributes == 3) {
        value = xmlTextReaderGetAttribute(reader, BAD_CAST("match"));
        func = xmlTextReaderGetAttribute(reader, BAD_CAST("func"));
    } else {
        Assert(false && "Wrong XML file format");
    }

    // creating temporiary object is not good idea
    // but we have no choice untill Attribute have constructor taking std::string*
    std::string temp(reinterpret_cast<const char *>(attrName));
    Attribute * attr = new Attribute(&temp, convertToMatchFunction(
                                         func), Attribute::Type::Subject);
    if (value != NULL) { //add value of the attribute if possible
        //[CR] consider create Attribute::addValue(char *) function
        std::string temp(reinterpret_cast<const char *>(value));
        attr->addValue(&temp);
    }
    currentAttribute = attr;

    if (xmlTextReaderIsEmptyElement(reader)) {
        Assert(value != NULL && "XML file format is wrong");
        //Attribute value is required to obtain the match value easier
        consumeSubjectMatch(value);
    }

    if (attributes == 2 || attributes == 3) {
        xmlFree(func);
    }
    xmlFree(value);
    xmlFree(attrName);
}

void Parser::handleMatch(xmlTextReaderPtr reader,
        Attribute::Type type)
{
    int attributes = xmlTextReaderAttributeCount(reader);

    xmlChar * func = NULL;
    xmlChar * value = NULL;
    xmlChar * attrName = xmlTextReaderGetAttribute(reader, BAD_CAST("attr")); //get the first attribute

    if (attributes == 2) {
        //match attribute ommited, text value will be used
        func = xmlTextReaderGetAttribute(reader, BAD_CAST("func"));
        //the content may be resource-attr or PCDATA
    } else if (attributes == 3) {
        value = xmlTextReaderGetAttribute(reader, BAD_CAST("match"));
        func = xmlTextReaderGetAttribute(reader, BAD_CAST("func"));
    } else {
        Assert(false && "Wrong XML file format");
    }

    // FunctionParam type is sybtype of Resource.
    // FunctionParam is used to storage attriburess of call functions.
    if (0 ==
        xmlStrncmp(attrName, BAD_CAST(TOKEN_PARAM),
                   xmlStrlen(BAD_CAST(TOKEN_PARAM))) && type ==
        Attribute::Type::Resource) {
        type = Attribute::Type::FunctionParam;
    }

    std::string temp(reinterpret_cast<const char*>(attrName));
    Attribute * attr = new Attribute(&temp, convertToMatchFunction(func), type);
    currentAttribute = attr;

    if (xmlTextReaderIsEmptyElement(reader)) {
        Assert(value != NULL && "XML is currupted");
        std::string tempVal(reinterpret_cast<const char*>(value));
        currentAttribute->addValue(&tempVal);
        consumeCurrentAttribute();
    }

    if (attributes == 2 || attributes == 3) {
        xmlFree(func);
    }
    xmlFree(value);
    xmlFree(attrName);
}

Policy::CombineAlgorithm Parser::convertToCombineAlgorithm(xmlChar* algorithm)
{
    switch (*algorithm) {
    case 'f':
        if (*(algorithm + 6) == 'a') { //first applicable
            return Policy::FirstApplicable;
        }
        return Policy::FirstTargetMatching;
    case 'd':
        return Policy::DenyOverride;
    case 'p':
        return Policy::PermitOverride;
    default:
        Assert(false && "Wrong combine algorithm name");
        return Policy::DenyOverride;
    }
}

ExtendedEffect Parser::convertToEffect(xmlChar *effect)
{
    switch (*effect) {
    case 'd':     //deny
        return Deny;
        break;
    case 'p':
        //permit, prompt-blanket, prompt-session, prompt-oneshot
        if (*(effect + 1) == 'e') {
            return ExtendedEffect(Permit, ruleId++);
        }
        switch (*(effect + 7)) {
        case 'b':
            return ExtendedEffect(PromptBlanket, ruleId++);
        case 's':
            return ExtendedEffect(PromptSession, ruleId++);
        case 'o':
            return ExtendedEffect(PromptOneShot, ruleId++);
        default:
            Assert(false && "Effect is Error");
            return ExtendedEffect();
        }
        break;
    default:
        Assert(false && "Effect is Error");
        return ExtendedEffect();
    }
    //return ExtendedEffect(Inapplicable); //unreachable statement
}

Attribute::Match Parser::convertToMatchFunction(xmlChar * func)
{
    if (func == NULL) {
        LogError("[ERROR] match function value is NULL");
        return Attribute::Match::Error;
    }

    if (*func == 'g') {
        return Attribute::Match::Glob;
    } else if (*func == 'e') {
        return Attribute::Match::Equal;
    } else if (*func == 'r') {
        return Attribute::Match::Regexp;
    } else {
        LogError("[ERROR] match function value is NULL");
        return Attribute::Match::Error;
    }
}

void Parser::handleAttr(xmlTextReaderPtr reader)
{
    xmlChar * attrValue = xmlTextReaderGetAttribute(reader, BAD_CAST("attr")); //get the first attribute
    Assert(attrValue != NULL && "Error while obtaining attribute");

    std::string temp(reinterpret_cast<const char*>(attrValue));
    currentAttribute->addValue(&temp);

    xmlFree(attrValue);
}

void Parser::consumeCurrentText()
{
    Assert(currentText != NULL);
    currentAttribute->addValue(currentText);
    delete currentText;

    currentText = NULL;
}

void Parser::consumeCurrentAttribute()
{
    Assert(currentAttribute != NULL);

    currentCondition->addAttribute(*currentAttribute);
    delete currentAttribute;

    currentAttribute = NULL;
}

void Parser::consumeCurrentSubject()
{
    Policy * policy = dynamic_cast<Policy *>(currentRoot->getElement());
    Assert(policy != NULL);
    policy->addSubject(currentSubject);
    //TODO maybe keep subjects not subject pointers in Policies and consume subjects here
    currentSubject = NULL;
}

void Parser::consumeCurrentCondition()
{
    Condition * temp = NULL;
    if (currentCondition != NULL) {
        if (currentCondition->getParent() != NULL) { //Condition is a child of another condition
            currentCondition->getParent()->addCondition(*currentCondition);
        } else { //Condition parent is a Rule
            Rule * rule = dynamic_cast<Rule *>(currentRoot->getElement());
            Assert(rule != NULL);
            rule->setCondition(*currentCondition);
        }
        temp = currentCondition->getParent();
        delete currentCondition;
    }
    currentCondition = temp;  //switch current condition ( it may be switched to NULL if condition's parent was rule
}

void Parser::consumeSubjectMatch(xmlChar * value)
{
    Assert(
        currentAttribute != NULL &&
        "consuming subject match without attribute set");

    if (currentSubject != NULL) {
        currentSubject->addNewAttribute(*currentAttribute);
        //[CR] matching/modyfing functions transform uri.host to uri ( etc. ) so strncmp is not needed, string equality will do
        if (!strncmp(currentAttribute->getName()->c_str(), "uri",
                     3) ||
            !strncmp(currentAttribute->getName()->c_str(), "id", 2)) {
            if (value != NULL) {
                currentSubject->setSubjectId(reinterpret_cast<const char *>(
                                                 value));
            } else if (currentAttribute->getValue()->size()) {
                currentSubject->setSubjectId(
                    currentAttribute->getValue()->front());
            } else {
                Assert(false);
            }
        }
    } else if (currentCondition != NULL) {
        currentCondition->addAttribute(*currentAttribute);
    }

    delete currentAttribute;
    currentAttribute = NULL;
}

void Parser::trim(std::string * str)
{
    std::string::size_type pos = str->find_last_not_of(whitespaces);
    if (pos != std::string::npos) {
        str->erase(pos + 1);
        pos = str->find_first_not_of(whitespaces);
        if (pos != std::string::npos) {
            str->erase(0, pos);
        }
    } else {
        str->erase(str->begin(), str->end());
        LogInfo("Warning, empty string as attribute value");
    }
}

// KW void Parser::canonicalize(const char * input, const char * output, CanonicalizationAlgorithm canonicalizationAlgorithm){
// KW
// KW     xmlDocPtr       doc =  xmlParseFile(input);
// KW     //xmlDocDump(stdout, doc);
// KW
// KW     if(doc == NULL)
// KW     {
// KW         LogError("Canonicalization error, cannot parser xml file");
// KW     }
// KW
// KW
// KW     int mode = -1;
// KW     if(canonicalizationAlgorithm == C14N)
// KW     {
// KW         mode = 0;
// KW     }
// KW     else if(canonicalizationAlgorithm == C14NEXCLUSIVE)
// KW     {
// KW         mode = 1;
// KW     }
// KW
// KW
// KW     xmlC14NDocSave(doc, NULL, mode, NULL, 0, output, 0);
// KW
// KW     xmlFreeDoc(doc);
// KW
// KW }

// KW int Parser::extractNodeToFile(xmlTextReaderPtr reader, const char * filename){
// KW
// KW        xmlNodePtr node = xmlTextReaderExpand(reader);
// KW        xmlBufferPtr buff = xmlBufferCreate();
// KW        xmlNodeDump(buff, node->doc, node, 0, 0);
// KW        FILE * file = fopen(filename, "w");
// KW        if(file == NULL){
// KW            LogError("Error while trying to open file "<<filename);
// KW            return -1;
// KW        }
// KW        int ret = xmlBufferDump(file, buff);
// KW        fclose(file);
// KW        xmlBufferFree(buff);
// KW        return ret;
// KW
// KW }

