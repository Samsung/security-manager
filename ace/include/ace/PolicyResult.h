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

#ifndef _SRC_ACCESS_CONTROL_COMMON_POLICY_RESULT_H_
#define _SRC_ACCESS_CONTROL_COMMON_POLICY_RESULT_H_

#include <dpl/assert.h>
#include <dpl/optional.h>
#include <dpl/optional_typedefs.h>

#include <ace/PolicyEffect.h>

typedef DPL::Optional<PolicyEffect> OptionalPolicyEffect;

class PolicyDecision
{
public:
    enum Value { NOT_APPLICABLE = -1 };

    PolicyDecision(PolicyEffect effect)
      : m_isPolicyEffect(true)
      , m_effect(effect)
    {}

    PolicyDecision(const PolicyDecision &decision)
      : m_isPolicyEffect(decision.m_isPolicyEffect)
      , m_effect(decision.m_effect)
    {}

    PolicyDecision(Value)
      : m_isPolicyEffect(false)
    {}

    bool operator==(const PolicyDecision &decision) const {
        return (m_isPolicyEffect
                 && decision.m_isPolicyEffect
                 && m_effect == decision.m_effect)
               || (!m_isPolicyEffect && !decision.m_isPolicyEffect);
    }

    bool operator==(Value) const {
        return !m_isPolicyEffect;
    }

    bool operator!=(const PolicyDecision &decision) const {
        return !(*this == decision);
    }

    bool operator!=(Value value) const {
        return !(*this == value);
    }

    OptionalPolicyEffect getEffect() const
    {
        if (!m_isPolicyEffect) {
            return OptionalPolicyEffect();
        }
        return OptionalPolicyEffect(m_effect);
    }

    std::ostream & toStream(std::ostream& stream) {
        if (m_isPolicyEffect)
            stream << m_effect;
        else
            stream << "NOT-APPLICABLE";
        return stream;
    }

private:
    bool m_isPolicyEffect;
    PolicyEffect m_effect;
};

inline static bool operator==(PolicyEffect e, const PolicyDecision &d) {
  return d.operator==(e);
}

inline static bool operator!=(PolicyEffect e, const PolicyDecision &d) {
  return !(e == d);
}

inline static std::ostream & operator<<(std::ostream& stream,
                                        PolicyDecision decision)
{
    return decision.toStream(stream);
}

class PolicyResult {
public:
    enum Value { UNDETERMINED = -2 };

    // This constructor is required by dpl controller and by dpl optional
    PolicyResult()
      : m_isDecision(false)
      , m_decision(PolicyDecision::Value::NOT_APPLICABLE) // don't care
    {}

    PolicyResult(PolicyEffect effect)
      : m_isDecision(true)
      , m_decision(effect)
    {}

    PolicyResult(const PolicyDecision &decision)
      : m_isDecision(true)
      , m_decision(decision)
    {}

    PolicyResult(const PolicyResult &result)
      : m_isDecision(result.m_isDecision)
      , m_decision(result.m_decision)
    {}

    PolicyResult(PolicyDecision::Value value)
      : m_isDecision(true)
      , m_decision(value)
    {}

    PolicyResult(Value)
      : m_isDecision(false)
      , m_decision(PolicyDecision::Value::NOT_APPLICABLE) // don't care
    {}

    bool operator==(const PolicyResult &result) const {
          return (m_isDecision
                && result.m_isDecision
                && m_decision == result.m_decision)
                || (!m_isDecision && !result.m_isDecision);
    }

    bool operator==(Value) const {
        return !m_isDecision;
    }

    bool operator!=(const PolicyResult &result) const {
        return !(*this == result);
    }

    bool operator!=(Value value) const {
        return !(*this == value);
    }

    OptionalPolicyEffect getEffect() const
    {
        if (!m_isDecision) {
            return OptionalPolicyEffect();
        }
        return m_decision.getEffect();
    }

    static int serialize(const PolicyResult &policyResult)
    {
        if (!policyResult.m_isDecision) {
            return BD_UNDETERMINED;
        } else if (policyResult.m_decision ==
            PolicyDecision::Value::NOT_APPLICABLE)
        {
            return BD_NOT_APPLICABLE;
        } else if (policyResult.m_decision == PolicyEffect::PROMPT_BLANKET) {
            return BD_PROMPT_BLANKET;
        } else if (policyResult.m_decision == PolicyEffect::PROMPT_SESSION) {
            return BD_PROMPT_SESSION;
        } else if (policyResult.m_decision == PolicyEffect::PROMPT_ONESHOT) {
            return BD_PROMPT_ONESHOT;
        } else if (policyResult.m_decision == PolicyEffect::PERMIT) {
            return BD_PERMIT;
        } else if (policyResult.m_decision == PolicyEffect::DENY) {
            return BD_DENY;
        }
        Assert(false && "Unknown value of policyResult.");
    }

    static PolicyResult deserialize(int dec){
        switch (dec) {
            case BD_DENY:
                return PolicyEffect::DENY;
            case BD_PERMIT:
                return PolicyEffect::PERMIT;
            case BD_PROMPT_ONESHOT:
                return PolicyEffect::PROMPT_ONESHOT;
            case BD_PROMPT_SESSION:
                return PolicyEffect::PROMPT_SESSION;
            case BD_PROMPT_BLANKET:
                return PolicyEffect::PROMPT_BLANKET;
            case BD_NOT_APPLICABLE:
                return PolicyDecision::Value::NOT_APPLICABLE;
            case BD_UNDETERMINED:
                return Value::UNDETERMINED;
        }
        Assert(false && "Broken database");
    }

    std::ostream & toStream(std::ostream& stream) {
        if (m_isDecision)
            stream << m_decision;
        else
            stream << "UNDETERMINED";
        return stream;
    }

private:
    static const int BD_UNDETERMINED = 6;
    static const int BD_NOT_APPLICABLE = 5;
    static const int BD_PROMPT_BLANKET = 4;
    static const int BD_PROMPT_SESSION = 3;
    static const int BD_PROMPT_ONESHOT = 2;
    static const int BD_PERMIT = 1;
    static const int BD_DENY = 0;

    bool m_isDecision;
    PolicyDecision m_decision;
};

inline static bool operator==(const PolicyDecision &d, const PolicyResult &r) {
    return r == d;
}

inline static bool operator!=(const PolicyDecision &d, const PolicyResult &r) {
    return !(d == r);
}

inline static bool operator==(const PolicyEffect &e, const PolicyResult &r) {
    return e == r;
}

inline static bool operator!=(const PolicyEffect &e, const PolicyResult &r) {
    return !(e == r);
}

inline static std::ostream & operator<<(std::ostream& stream,
                                        PolicyResult result)
{
    return result.toStream(stream);
}

struct ExtendedPolicyResult {
    ExtendedPolicyResult(const PolicyResult pr = PolicyEffect::DENY, int rule = -1)
      : policyResult(pr)
      , ruleId(rule)
    {}
    PolicyResult policyResult;
    int ruleId;
};

typedef DPL::Optional<ExtendedPolicyResult> OptionalExtendedPolicyResult;

#endif // _SRC_ACCESS_CONTROL_COMMON_POLICY_RESULT_H_
