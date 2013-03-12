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
/**
 *
 *
 * @file       IAttribute.h
 * @author     Grzegorz Krawczyk (g.krawczyk@samsung.com)
 * @version    0.1
 * @brief
 */

#ifndef ACCESS_CONTROL_DAO_BASEATTRIBUTE_H_
#define ACCESS_CONTROL_DAO_BASEATTRIBUTE_H_

#include <list>
#include <set>
#include <string>
#include <dpl/shared_ptr.h>
#include <dpl/assert.h>

namespace AceDB {

class BaseAttribute;
typedef DPL::SharedPtr<BaseAttribute> BaseAttributePtr;

class BaseAttribute
{

  public:
    /**
     * Types of attributes
     */
    enum class Type { Subject, Environment, Resource, FunctionParam,
                      WidgetParam, Undefined };

    struct UnaryPredicate
    {
      public:
        UnaryPredicate(const AceDB::BaseAttribute *comp = NULL) :
            m_priv(comp)
        {
        }

        bool operator()(const AceDB::BaseAttributePtr &comp)
        {
            Assert(m_priv != NULL);
            if (m_priv->getName()->compare(*comp->getName()) != 0) {
                return false;
            }
            return m_priv->getType() == comp->getType();
        }

        bool operator()(const AceDB::BaseAttributePtr &comp1,
                        const AceDB::BaseAttributePtr &comp2)
        {
            if (comp1->getType() != comp2->getType()) {
                return comp1->getType() < comp2->getType();
            }
            return comp1->getName()->compare(*comp2->getName()) < 0;
        }

      private:
          const AceDB::BaseAttribute *m_priv;
    };

  public:
    BaseAttribute() :
        m_typeId(Type::Undefined),
        m_undetermindState(false)
    {}

    virtual void setName(const std::string& name)
    {
        m_name = name;
    }
    virtual void setName(const std::string* name)
    {
        m_name = *name;
    }

    virtual void setType(const Type& type)
    {
        m_typeId = type;
    }
    virtual Type getType() const
    {
        return m_typeId;
    }

    virtual const std::string* getName() const
    {
        return &m_name;
    }

    //TODO think
    virtual void setUndetermind(bool tmp)
    {
        m_undetermindState = tmp;
    }
    virtual bool isUndetermind() const
    {
        return m_undetermindState;
    }
    virtual std::list<std::string> * getValue() const
    {
        return const_cast<std::list<std::string>* >(&value);
    }
    virtual bool isValueEmpty() const
    {
        return value.empty();
    }

    virtual void setValue(const std::list<std::string>& arg)
    {
        value = arg;
    }

    virtual ~BaseAttribute()
    {
    }

    static const char * typeToString(Type type);

    virtual std::string toString() const;

  protected:
    std::string m_name;
    Type m_typeId;
    bool m_undetermindState;
    std::list<std::string> value; //string bag list
};

typedef std::set<BaseAttributePtr, BaseAttribute::UnaryPredicate> BaseAttributeSet;

}

#endif
