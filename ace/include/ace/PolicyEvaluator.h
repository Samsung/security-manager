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
//  @ File Name : PolicyEvaluator.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#ifndef _POLICY_EVALUATOR_H
#define _POLICY_EVALUATOR_H

#include <memory>
#include <set>
#include <string>

#include <dpl/event/event_listener.h>
#include <dpl/log/log.h>
#include <dpl/noncopyable.h>

#include <ace/AsyncVerdictResultListener.h>
#include <ace/Attribute.h>
#include <ace/ConfigurationManager.h>
#include <ace/Constants.h>
#include <ace/Effect.h>
#include <ace/Policy.h>
#include <ace/PolicyInformationPoint.h>
#include <ace/PolicyResult.h>
#include <ace/Request.h>
#include <ace/Subject.h>
#include <ace/Verdict.h>
#include <ace/UserDecision.h>
#include <ace/CombinerImpl.h>


class PolicyEvaluator : DPL::Noncopyable
{
  protected:

    /**
     * Internal method used to initiate policy evaluation. Called after attribute set has been fetched
     * by PIP.
     * @param root root of the policies tree to be evaluated
     */
    virtual ExtendedEffect evaluatePolicies(const TreeNode * root);

    // !! DEPRECATED !!
    enum updateErrors
    {
        POLICY_PARSING_SUCCESS = 0,
        POLICY_FILE_ERROR = 1,
        PARSER_CREATION_ERROR,
        POLICY_PARSING_ERROR
    };
  private:
    AttributeSet m_attributeSet;

    TreeNode *m_uniform_policy, *m_wac_policy, *m_tizen_policy;
    std::string m_currentPolicyFile;
    PolicyType m_policy_to_use;

    Combiner * m_combiner;
    AsyncVerdictResultListener * m_verdictListener;
    PolicyInformationPoint * m_pip;

    /**
     * @return current policy Tree acc. to m_policy_to_use
     */
    TreeNode * getCurrentPolicyTree();

    /**
     * Method used to extract attributes from subtree defined by PolicySet
     * @param root original TreeStructure root node
     * @param newRoot copy of TreeStructure containing only policies that matches current request
     *
     */
    void extractAttributesFromSubtree(const TreeNode *root);

    /**
     * Method used to extract attributes from Tree Structure
     * @return pointer to set of attributes needed to evaluate current request
     * @return if extraction has been successful
     * TODO return reducte tree structure
     * TODO change comments
     */
    bool extractAttributesFromRules(const TreeNode *);

    /**
     * Extracts attributes from target of a given policy that are required to be fetched by PIP
     */
    void extractTargetAttributes(const Policy *policy);
    bool extractAttributes(TreeNode*);

    OptionalExtendedPolicyResult getPolicyForRequestInternal(bool fromCacheOnly);
    PolicyResult effectToPolicyResult(Effect effect);

    /**
     * Return safe policy tree in case of error with loading policy from file
     */
    TreeNode * getDefaultSafePolicyTree(void);

  public:
    PolicyEvaluator(PolicyInformationPoint * pip);

    bool extractAttributesTest()
    {
        m_attributeSet.clear();
        if (!extractAttributes(m_uniform_policy)) {
            LogInfo("Warnign attribute set cannot be extracted. Returning Deny");
            return true;
        }

        return extractAttributes(m_uniform_policy);
    }

    AttributeSet * getAttributeSet()
    {
        return &m_attributeSet;
    }

    virtual bool initPDP();
    virtual ~PolicyEvaluator();
    virtual ExtendedPolicyResult getPolicyForRequest(const Request &request);
    virtual OptionalExtendedPolicyResult getPolicyForRequestFromCache(
        const Request &request);
    virtual OptionalExtendedPolicyResult getPolicyForRequest(const Request &request,
                                                     bool fromCacheOnly);
    bool fillAttributeWithPolicy();

    virtual int updatePolicy(const char *);
    // This function updates policy from well known locations
    virtual void updatePolicy();

    std::string getCurrentPolicy();
};

#endif  //_POLICYEVALUATOR_H
