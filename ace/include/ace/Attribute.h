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
//  @ File Name : Attribute.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#if !defined(_ATTRIBUTE_H)
#define _ATTRIBUTE_H

#include <string>
#include <iostream>
#include <set>
#include <list>

#include <ace-dao-ro/BaseAttribute.h>

class Attribute : public AceDB::BaseAttribute
{
  public:
    /**
     * Types of match functions
     */
    enum class Match { Equal, Glob, Regexp, Error };
    /**
     * Types of attribute value modifiers
     */
    enum class Modifier { Non, Scheme, Authority, SchemeAuthority, Host, Path };
    /**
     * Possible match results
     */
    enum class MatchResult { MRUndetermined = -1, MRFalse = 0, MRTrue = 1};

  public:

    /**
     * New attribute constructor
     * @param name name of the new attribute
     * @param matchFunction match function used in the attribute
     * @param type attribute type
     */
    Attribute(const std::string *name,
              const Match matchFunction,
              const Type type);


    /**
     * Constructor used to create default attribute ( used for unit tests )
     * @param nm name of the default attribute
     */
    Attribute(const std::string& nm) :
        matchFunction(Match::Error),
        modifierFunction(Modifier::Non)
    {
        m_name = nm;
        m_typeId = Type::Subject;
        m_undetermindState = false;
    }

    /**
     * Destructor
     */
    virtual ~Attribute();

    std::list<std::string> * getValue() const
    {
        return AceDB::BaseAttribute::getValue();
    }
    Match getMatchFunction() const
    {
        return matchFunction;
    }

    /*  --- Setters --- */
    void addValue (const std::string *value);

    MatchResult  matchAttributes(const BaseAttribute *) const;

    /**
     * Operator used in for attribute set,used to distinguished only attribute names
     * It cannot take attribute type into consideration
     */
    bool operator< (const Attribute & obj) const
    {
        int result = this->m_name.compare(*obj.getName());
        if (result == 0) { //If names are equal check attribute types
            if (this->m_typeId < obj.getType()) {
                result = -1;
            } else if (this->m_typeId > obj.getType()) {
                result = 1;
            }
        }
        //If result is negative that means that 'this' was '<' than obj
        return result < 0;
    }

     /** Checks if object type is equal to argument */
    bool instanceOf(Type type_)
    {
        return type_ == m_typeId;
    }

    friend std::ostream & operator<<(std::ostream & out,
                                     const Attribute & attr);

  protected:

    bool searchAndCut(const char *);

    /*
     *  URI definition from rfc2396
     *
     *  <scheme>://<authority><path>?<query>
     *  Each of the components may be absent, apart from the scheme.
     *  Host is a part of authority as in definition below:
     *
     *  authority     = server | reg_name
     *  server        = [ [ userinfo "@" ] hostport ]
     *  <userinfo>@<host>:<port>
     *
     *  Extract from rfc2396
     *  The authority component is preceded by a double slash "//" and is
     *  terminated by the next slash "/", question-mark "?", or by the end of
     *  the URI.  Within the authority component, the characters ";", ":",
     * "@", "?", and "/" are reserved.
     *
     *  Modifiers should return pointer to empty string if given part of string was empty.
     *  Modifiers should return NULL if the string to be modified was not an URI.
     */
    std::string * uriScheme(const std::string *) const;
    std::string * uriAuthority(const std::string *) const;
    std::string * uriSchemeAuthority(const std::string *) const;
    std::string * uriHost(const std::string *) const;
    std::string * uriPath(const std::string *) const;
    std::string * applyModifierFunction(const std::string * val) const;

    bool parse(const std::string *input,
            std::string *part) const;
    bool find_error(const std::string *part) const;

    bool checkScheme(const std::string *scheme) const;
    bool checkAuthority(const std::string *scheme) const;
    std::string * getHost(const std::string *scheme) const;
    bool checkPath(const std::string *scheme) const;

    bool isSchemeAllowedCharacter(int c) const;
    bool isSegmentAllowedCharacter(int c) const;
    bool isUserInfoAllowedString(const std::string *str) const;
    bool isHostAllowedString(const std::string *str) const;
    bool isHostNameAllowedString(const std::string * str) const;
    bool isIPv4AllowedString(const std::string * str) const;
    bool isDomainLabelAllowedString(const char * data,
                                    int lenght) const;
    bool isTopLabelAllowedString(const char* data,
                                 int lenght) const;

    bool isUnreserved(int c) const;
    bool isAlphanum(int c) const;
    bool isEscaped(const char esc[3]) const;
    bool isHex(int c) const;

    MatchResult lists_comparator(
        const std::list<std::string> *first,
        const std::list<std::string> *second,
        MatchResult (*comparator)(const std::string *,
                                  const std::string *)) const;

    /**
     *  Map used to check if character is a 'mark'
     */
    static const bool mark[256];
    /**
     *  Map used to check if character is a 'digit'
     *
     */
    static const bool digit[256];
    /**
     * Map used to check if character is an 'alphanumeric' value
     *
     */
    static const bool alpha[256];

  protected:
    Match matchFunction;
    Modifier modifierFunction;
};

typedef AceDB::BaseAttributeSet AttributeSet;

//TODO remove later or ifdef debug methods
void printAttributes(const AttributeSet& attrs);
void printAttributes(const std::list<Attribute> & attrs);

#endif  //_ATTRIBUTE_H
