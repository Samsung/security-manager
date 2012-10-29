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
//  @ File Name : PolicyEvaluator.cpp
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//
#include <dpl/assert.h>
#include <dpl/foreach.h>

#include <ace/Attribute.h>
#include <ace/PolicyEvaluator.h>
#include <ace/TreeNode.h>
#include <ace/Policy.h>
#include <ace/Rule.h>
#include <ace/Attribute.h>
#include <ace/SettingsLogic.h>
#include <ace-dao-rw/AceDAO.h>
#include <ace-dao-ro/PreferenceTypes.h>
#include <ace/parser.h>

using namespace AceDB;

PolicyEvaluator::~PolicyEvaluator()
{
    delete m_combiner;
}

PolicyEvaluator::PolicyEvaluator(PolicyInformationPoint * pip) :
    m_uniform_policy(NULL),
    m_wac_policy(NULL),
    m_tizen_policy(NULL),
    m_policy_to_use(PolicyType::WAC2_0),
    m_combiner(new CombinerImpl()),
    m_verdictListener(NULL),
    m_pip(pip)
{}

bool PolicyEvaluator::initPDP()
{
    updatePolicy();
    // TODO change return value someday to void?
    return true;
}

bool PolicyEvaluator::fillAttributeWithPolicy()
{
    if (m_attributeSet.empty()) {
        if (!extractAttributes(m_uniform_policy)) {
            LogInfo("Warning attribute set cannot be extracted. "
                    "Returning Deny");
            return false;
        }
        // Adding widget type attribute to distinguish WAC/Tizen widgets
        /**
         * This special attribute of WidgetParam type is handled
         * in PolicyInformationPoint, it is based on WidgetType
         * fron WRT database.
         *
         * It is needed to distinguish cached policy results and cached prompt
         * responses for different policies (WAC/Tizen/any possible
         * other in the future).
         */
        AceDB::BaseAttributePtr attribute(new AceDB::BaseAttribute());
        attribute->setName(POLICY_WIDGET_TYPE_ATTRIBUTE_NAME);
        attribute->setType(AceDB::BaseAttribute::Type::WidgetParam);
        m_attributeSet.insert(attribute);
        AceDAO::addAttributes(m_attributeSet);
    } else {
        LogDebug("Required attribute set already loaded");
    }
    return true;
}

PolicyResult PolicyEvaluator::effectToPolicyResult(Effect effect)
{
    if (Effect::Deny == effect) {
        return PolicyEffect::DENY;
    }
    if (Effect::Undetermined == effect) {
        return PolicyResult::Value::UNDETERMINED;
    }
    if (Effect::PromptOneShot == effect) {
        return PolicyEffect::PROMPT_ONESHOT;
    }
    if (Effect::PromptSession == effect) {
        return PolicyEffect::PROMPT_SESSION;
    }
    if (Effect::PromptBlanket == effect) {
        return PolicyEffect::PROMPT_BLANKET;
    }
    if (Effect::Permit == effect) {
        return PolicyEffect::PERMIT;
    }
    if (Effect::Inapplicable == effect) {
        return PolicyDecision::Value::NOT_APPLICABLE;
    }
    return PolicyEffect::DENY;
}

OptionalExtendedPolicyResult PolicyEvaluator::getPolicyForRequestInternal(
        bool fromCacheOnly)
{
    //ADD_PROFILING_POINT("Search cached verdict in database", "start");

    OptionalExtendedPolicyResult result = AceDAO::getPolicyResult(m_attributeSet);

    //ADD_PROFILING_POINT("Search cached verdict in database", "stop");

    if (fromCacheOnly || !result.IsNull()) {
        return result;
    }

    //ADD_PROFILING_POINT("EvaluatePolicy", "start");

    ExtendedEffect policyEffect = evaluatePolicies(getCurrentPolicyTree());

    //ADD_PROFILING_POINT("EvaluatePolicy", "stop");

    LogDebug("Policy effect is: " << toString(policyEffect.getEffect()));

    ExtendedPolicyResult exResult(
        effectToPolicyResult(policyEffect.getEffect()),
        policyEffect.getRuleId());

    AceDAO::setPolicyResult(this->m_attributeSet, exResult);
    return OptionalExtendedPolicyResult(exResult);
}

// +----------------+---------+---------+------+--------+
// |\User setting   | PERMIT  | PROMPT* | DENY | DEF    |
// |      \         |         |         |      |        |
// |Policy result\  |         |         |      |        |
// |----------------+---------+---------+------+--------+
// |PERMIT          | PERMIT  | PROMPT* | DENY | PERMIT |
// |----------------+---------+---------+------+--------+
// |PROMPT*         | PROMPT* | PR MIN  | DENY | PROMPT*|
// |----------------+---------+---------+------+--------+
// |DENY            | DENY    | DENY    | DENY | DENY   |
// |----------------+---------+---------+------+--------+
// |UNDETERMIND     | UNDET   | UNDET   | DENY | UNDET  |
// |----------------+---------+---------+------+--------+
// |NOT_AP          | PEMIT   | PROMPT* | DENY | NOT_AP |
// +----------------+---------+---------+------+--------+

static PolicyResult getMostRestrict(
        PreferenceTypes globalPreference,
        const PolicyResult &policyResult)
{
    if (globalPreference == PreferenceTypes::PREFERENCE_PERMIT
            && policyResult == PolicyEffect::PERMIT) {
        return PolicyEffect::PERMIT;
    }

    if (globalPreference == PreferenceTypes::PREFERENCE_DENY
            || policyResult == PolicyEffect::DENY) {
        return PolicyEffect::DENY;
    }

    if (policyResult == PolicyResult::UNDETERMINED) {
        return PolicyResult::UNDETERMINED;
    }

    if (globalPreference == PreferenceTypes::PREFERENCE_DEFAULT) {
        return policyResult;
    }

    if (globalPreference == PreferenceTypes::PREFERENCE_ONE_SHOT_PROMPT
            || policyResult == PolicyEffect::PROMPT_ONESHOT) {
        return PolicyEffect::PROMPT_ONESHOT;
    }

    if (globalPreference == PreferenceTypes::PREFERENCE_SESSION_PROMPT
            || policyResult == PolicyEffect::PROMPT_SESSION) {
        return PolicyEffect::PROMPT_SESSION;
    }

    if (globalPreference == PreferenceTypes::PREFERENCE_BLANKET_PROMPT
            || policyResult == PolicyEffect::PROMPT_BLANKET) {
        return PolicyEffect::PROMPT_BLANKET;
    }

    return PolicyEffect::PERMIT;
}

OptionalExtendedPolicyResult PolicyEvaluator::getPolicyForRequestFromCache(
        const Request &request)
{
    return getPolicyForRequest(request, true);
}

ExtendedPolicyResult PolicyEvaluator::getPolicyForRequest(const Request &request)
{
    auto result = this->getPolicyForRequest(request, false);
    Assert(!result.IsNull()
                    && "Policy always has to be evaluated to valid state");
    return *result;
}

OptionalExtendedPolicyResult PolicyEvaluator::getPolicyForRequest(
        const Request &request,
        bool fromCacheOnly)
{
    //ADD_PROFILING_POINT("getPolicyForRequest", "start");
    m_attributeSet.clear();

    switch (request.getAppType()) {
        case Request::APP_TYPE_TIZEN:
            m_policy_to_use = PolicyType::Tizen;
            LogDebug("==== Using Tizen policy ====");
            break;
        case Request::APP_TYPE_WAC20:
            m_policy_to_use = PolicyType::WAC2_0;
            LogDebug("==== Using WAC policy ====");
            break;
        default:
            LogError("Unsupported(unknown) widget type. Access denied.");
            return OptionalExtendedPolicyResult(
                ExtendedPolicyResult(PolicyEffect::DENY));
    }

    try {
        // Check which attributes should be used
        // memory alocated, free in destructor
        //ADD_PROFILING_POINT("getAttributes", "start");
        AceDB::AceDAO::getAttributes(&m_attributeSet);
        //ADD_PROFILING_POINT("getAttributes", "stop");

        // If attributes can't be resolved then check the policy
        if (!fillAttributeWithPolicy()) {
            //ADD_PROFILING_POINT("getPolicyForRequest", "stop");
            return OptionalExtendedPolicyResult(
                ExtendedPolicyResult(PolicyEffect::DENY));
        }

        //ADD_PROFILING_POINT("getAttributesValues", "start");
        m_pip->getAttributesValues(&request, &m_attributeSet);
        //ADD_PROFILING_POINT("getAttributesValues", "stop");
        LogDebug("==== Attributes set by PIP ====");
        printAttributes(m_attributeSet);
        LogDebug("==== End of attributes set by PIP ====");

        OptionalExtendedPolicyResult policyResult = getPolicyForRequestInternal(
                fromCacheOnly);

        if (policyResult.IsNull()) {
            if (!fromCacheOnly) {
                LogError("Policy evaluated to NULL value");
                Assert(false && "Policy evaluated to NULL value");
            }
            return OptionalExtendedPolicyResult::Null;
        }
        LogDebug("==== getPolicyForRequestInternal result (PolicyResult): "
                 << policyResult->policyResult << "=====");

        PreferenceTypes globalPreference =
                SettingsLogic::findGlobalUserSettings(request);

        auto ret = getMostRestrict(globalPreference, policyResult->policyResult);
        //ADD_PROFILING_POINT("getPolicyForRequest", "stop");
        return OptionalExtendedPolicyResult(
            ExtendedPolicyResult(ret, policyResult->ruleId));

    } catch (AceDB::AceDAO::Exception::DatabaseError &e) {
        LogError("Database error");
        DPL::Exception::DisplayKnownException(e);
        //ADD_PROFILING_POINT("getPolicyForRequest", "stop");
        return OptionalExtendedPolicyResult(
            ExtendedPolicyResult(PolicyEffect::DENY));
    }
}

bool PolicyEvaluator::extractAttributes(TreeNode* policyTree)
{
    if (NULL == policyTree) {
        return false;
    }

    //We check if root target matches. In general the root's target should
    //be empty. Otherwise it would have to have all the subjects available
    //specified but just to be on the safe side (and for tests) this checking
    const Policy * policy =
            dynamic_cast<const Policy *>(policyTree->getElement());
    Assert(policy != NULL
                  && "Policy element has been null while attribute extracting");

    extractTargetAttributes(policy);
    extractAttributesFromSubtree(policyTree); //Enter recursion

    return true;
}

void PolicyEvaluator::extractTargetAttributes(const Policy *policy)
{
    std::list<const Subject *>::const_iterator it =
            policy->getSubjects()->begin();
    for (; it != policy->getSubjects()->end(); ++it) {
        const std::list<Attribute> & attrList = (*it)->getTargetAttributes();
        FOREACH(it2, attrList)
        {
            BaseAttributePtr attr(
                    new Attribute((*it2).getName(), (*it2).getMatchFunction(),
                            (*it2).getType()));
            m_attributeSet.insert(attr);
        }
    }
}

TreeNode * PolicyEvaluator::getCurrentPolicyTree()
{
    TreeNode * currentPolicy = NULL;
    switch (m_policy_to_use) {
    case PolicyType::Tizen: {
        currentPolicy = m_tizen_policy;
        break;}
    case PolicyType::WAC2_0: {
        currentPolicy = m_wac_policy;
        break;}
    default: {
        LogError("Invalid policy type to use");}
    }
    return currentPolicy;
}

/**
 *
 * @param *root - the root of the original (full) subtree of politics
 * @param *newRoot - the pointer to the root of the copy (reduced) subtree of politics
 */
void PolicyEvaluator::extractAttributesFromSubtree(const TreeNode *root)
{
    const ChildrenSet & children = root->getChildrenSet();

    for (std::list<TreeNode *>::const_iterator it = children.begin();
            it != children.end(); ++it) {
        TreeNode * node = *it;
        if (node->getTypeID() != TreeNode::Policy
                && node->getTypeID() != TreeNode::PolicySet) {
            //It is not a policy so we may be sure that we have already
            //checked that SubjectId matches
            //Add new node to new tree and extract attributes

            extractAttributesFromRules(node);
        } else { //TreeNode is a Policy or PolicySet
            const Policy * policy =
                    dynamic_cast<const Policy *>(node->getElement());
                    //We will be needing also the attributes from target
            if (policy) {
                extractTargetAttributes(policy);
            } else {
                LogError(" extractAttributesFromSubtree policy=NULL");
            }
            //Enter recursion
            extractAttributesFromSubtree(node);
        }
    }
}

bool PolicyEvaluator::extractAttributesFromRules(const TreeNode *root)
{
    Assert(root->getTypeID() == TreeNode::Rule
       && "Tree structure, extracting attributes from node that is not a rule");
    Rule * rule = dynamic_cast<Rule *>(root->getElement());Assert
    (rule != NULL);
    //Get attributes from rule
    rule->getAttributes(&m_attributeSet);

    //[CR] consider returned value, because its added only to eliminate errors
    return true;
}

ExtendedEffect PolicyEvaluator::evaluatePolicies(const TreeNode * root)
{
    if (root == NULL) {
        LogInfo("Error: policy tree doesn't exist. "
                "Probably xml file is missing");
        return Deny;
    }

    if (m_attributeSet.empty()) {
        LogInfo("Warning: evaluatePolicies: attribute set was empty");
    }
    m_combiner->setAttributeSet(&m_attributeSet);
    return m_combiner->combinePolicies(root);
}


int PolicyEvaluator::updatePolicy(const char* newPolicy)
{
    LogError("PolicyEvaluator::updatePolicy is DEPRECATED");
    ConfigurationManager* configMgr = ConfigurationManager::getInstance();
    if (NULL == configMgr) {
        LogError("ACE fatal error: failed to create configuration manager");
        return POLICY_PARSING_ERROR;
    }
    int result = POLICY_PARSING_SUCCESS;
    if (newPolicy == NULL) {
        LogError("Policy Update: incorrect policy name");
        return POLICY_FILE_ERROR;
    }
    LogDebug("Starting update policy: " << newPolicy);

    Parser parser;
    TreeNode *backup = m_uniform_policy;

    m_uniform_policy = parser.parse(newPolicy,
            configMgr->getFullPathToPolicyXMLSchema());

    if (NULL == m_uniform_policy) {
        m_uniform_policy = backup;
        LogError("Policy Update: corrupted policy file");
        result = POLICY_PARSING_ERROR;
    } else {
        m_currentPolicyFile = newPolicy;
        m_wac_policy = m_uniform_policy;  //we must be able to use WAC widgets
        m_tizen_policy = m_uniform_policy;//we must be able to use Tizen widgets
        m_attributeSet.clear();
        backup->releaseResources();
        LogInfo("Policy Update: successful.");
        try {
            AceDAO::resetDatabase();   // TODO: this is strange, but this
                                       // method is deprecated so not changing
                                       // it (will disappear with entire method)
        } catch (AceDAO::Exception::DatabaseError &e) {
        }
    }
    return result;
}

TreeNode * PolicyEvaluator::getDefaultSafePolicyTree(void)
{
    Policy * policy = new Policy;
    Rule * rule = new Rule;
    TreeNode * mainTree = NULL,
             * childTree = NULL;

    policy->setCombineAlgorithm(Policy::CombineAlgorithm::DenyOverride);
    rule->setEffect(Deny);

    mainTree = new TreeNode(m_uniform_policy, TreeNode::Policy, policy);
    childTree = new TreeNode(mainTree, TreeNode::Rule, rule);
    mainTree->addChild(childTree);

    LogError("Loading default safe policy tree");
    return mainTree;
}

void PolicyEvaluator::updatePolicy()
{
    ConfigurationManager *configMgr = ConfigurationManager::getInstance();
    Assert(NULL != configMgr && "ACE fatal error: failed to "
           "create configuration manager");
    AceDAO::clearPolicyCache();
    if (NULL != m_uniform_policy) {
        m_uniform_policy->releaseResources();
    }
    Parser parserWac, parserTizen;
    m_wac_policy = parserWac.parse(
            configMgr->getFullPathToPolicyFile(PolicyType::WAC2_0),
            configMgr->getFullPathToPolicyXMLSchema());
    if (NULL == m_wac_policy) {
        LogError("ACE fatal error: cannot parse XML file (WAC policy)");
        m_wac_policy = getDefaultSafePolicyTree();
    }
    m_tizen_policy = parserTizen.parse(
            configMgr->getFullPathToPolicyFile(PolicyType::Tizen),
            configMgr->getFullPathToPolicyXMLSchema());
    if (NULL == m_tizen_policy) {
        LogError("ACE fatal error: cannot parse XML file (Tizen policy)");
        m_tizen_policy = getDefaultSafePolicyTree();
    }
    // Policy set is usefull for releasing all policies in case of
    // policy change
    Policy * policySet = new PolicySet();
    policySet->setCombineAlgorithm(Policy::CombineAlgorithm::DenyOverride);
    m_uniform_policy = new TreeNode(NULL, TreeNode::PolicySet, policySet);
    m_uniform_policy->addChild(m_wac_policy);
    m_uniform_policy->addChild(m_tizen_policy);

    // Creating attribute set for the first time after loading policy
    // to speed up queries
    m_attributeSet.clear();
    fillAttributeWithPolicy();
}

std::string PolicyEvaluator::getCurrentPolicy()
{
    LogError("PolicyEvaluator::getCurrentPolicy is DEPRECATED");
    return m_currentPolicyFile;
}

const char * toString(Validity validity)
{
    switch (validity) {
    case Validity::ONCE:
        return "Once";
        break;
    case Validity::SESSION:
        return "Session";
    case Validity::ALWAYS:
        return "Always";
    default:
        return "WRONG VALIDITY";
    }
}

const char * toString(Verdict verdict)
{
    switch (verdict) {
    case Verdict::VERDICT_PERMIT:
        return "Permit";
    case Verdict::VERDICT_DENY:
        return "Deny";
    case Verdict::VERDICT_INAPPLICABLE:
        return "Inapplicable";
    case Verdict::VERDICT_UNKNOWN:
        return "Unknown";
    case Verdict::VERDICT_UNDETERMINED:
        return "Undetermined";
    case Verdict::VERDICT_ERROR:
        return "Error";
    case Verdict::VERDICT_ASYNC:
        return "Async";
    default:
        return "Wrong verdict value";
    }
}
