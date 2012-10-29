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

#include <fnmatch.h>
#include <pcrecpp.h>
#include <sstream>
#include <dpl/foreach.h>
#include <dpl/log/log.h>
#include <ace/Attribute.h>

const bool Attribute::alpha[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0,
    0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0
};
const bool Attribute::digit[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0
};

const bool Attribute::mark[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0
};

bool Attribute::searchAndCut(const char *str)
{
    //TODO
    size_t pos = m_name.rfind(str);
    if (pos == std::string::npos) {
        return false;
    }
    if ((strlen(str) + pos) == m_name.size()) {
        m_name.erase(pos, std::string::npos);
        return true;
    }
    return false;
}

Attribute::Attribute(const std::string *name,
                     const Match matchFunc,
                     const Type type_) :
    matchFunction(matchFunc)
{
    m_name = *name;
    m_typeId = type_;
    m_undetermindState = false;
    if (matchFunction != Match::Equal
        && matchFunction != Match::Glob
        && matchFunction != Match::Regexp)
    {
        //LogDebug("MID: " << matchFunction);
        Assert(0 && "Match function problem");
    }

    if (searchAndCut(".scheme")) {
        modifierFunction = Modifier::Scheme;
    } else if (searchAndCut(".authority")) {
        modifierFunction = Modifier::Authority;
    } else if (searchAndCut(".scheme-authority")) {
        modifierFunction = Modifier::SchemeAuthority;
    } else if (searchAndCut(".host")) {
        modifierFunction = Modifier::Host;
    } else if (searchAndCut(".path")) {
        modifierFunction = Modifier::Path;
    } else {
        modifierFunction = Modifier::Non;
    }
}

static Attribute::MatchResult equal_comparator(const std::string *first,
                                               const std::string *second)
{
    if((*first) == (*second)) {
        return Attribute::MatchResult::MRTrue;
    }
    return  Attribute::MatchResult::MRFalse;
}

static Attribute::MatchResult glob_comparator(const std::string *first,
        const std::string *second)
{
    // order is important
    if (!fnmatch(first->c_str(), second->c_str(), 0)) {
        return Attribute::MatchResult::MRTrue;
    }
    return  Attribute::MatchResult::MRFalse;
}

static Attribute::MatchResult regexp_comparator(const std::string *first,
                                                const std::string *second)
{
    // order is important
    pcrecpp::RE re(first->c_str());
    if (re.FullMatch(second->c_str())) {
        return Attribute::MatchResult::MRTrue;
    }
    return  Attribute::MatchResult::MRFalse;
}

Attribute::MatchResult Attribute::lists_comparator(
        const std::list<std::string> *first,
        const std::list<std::string> *second,
        Attribute::MatchResult (*comparator)(const std::string *,
                                             const std::string *)) const
{
    //NOTE: BONDI defines all availabe matching function as: if some string from first input bag
    //matches some input string from second input bag, so it's required to find only one matching string
    MatchResult result = MatchResult::MRFalse;

    for (std::list<std::string>::const_iterator second_iter = second->begin();
         (second_iter != second->end()) && (result != MatchResult::MRTrue);
         ++second_iter)
    {
        std::string *modified_value = applyModifierFunction(&(*second_iter));
        //Value was not an URI, it will be removed from the string bag (ignored)
        if (modified_value == NULL) {
            continue;
        }

        for (std::list<std::string>::const_iterator first_iter = first->begin();
             first_iter != first->end();
             ++first_iter) {
            //Compare attributes
            if ((*comparator)(&(*first_iter), modified_value) == MatchResult::MRTrue) {
                result = MatchResult::MRTrue;
                break; //Only one match is enough
            }
        }
        if (modified_value) {
            delete modified_value;
            modified_value = NULL;
        }
    }

    if (result == MatchResult::MRTrue) {
        LogDebug("Returning TRUE");
    } else if (result == MatchResult::MRFalse) {
        LogDebug("Returning FALSE");
    } else if (result == MatchResult::MRUndetermined) {
        LogDebug("Returning UNDETERMINED");
    }
    return result;
}

std::string * Attribute::applyModifierFunction(const std::string * val) const
{
    std::string * result = NULL;
    switch (modifierFunction) {
    case Modifier::Scheme:
        result = uriScheme(val);
        break;
    case Modifier::Authority:
        result = uriAuthority(val);
        break;
    case Modifier::SchemeAuthority:
        result = uriSchemeAuthority(val);
        break;
    case Modifier::Host:
        result = uriHost(val);
        break;
    case Modifier::Path:
        result = uriPath(val);
        break;
    default:
        result = new std::string(*val);
    }

    return result;
}

/**
 * this - attribute obtained from xmlPolicy tree
 * attribute - attribute obtained from PIP
 */
Attribute::MatchResult Attribute::matchAttributes(
        const BaseAttribute *attribute) const
{
    std::string tempNam = *(attribute->getName());
    std::string tempVal;
    std::string myVal;

    if (!(attribute->getValue()->empty())) {
        tempVal = attribute->getValue()->front();
    }

    if (!(this->value.empty())) {
        myVal = this->value.front();
    }

    LogDebug("Comparing attribute: " << this->m_name << "(" <<
        myVal << ") with: " << tempNam <<
        "(" << tempVal << ")");

    Assert(
        (this->m_name == *(attribute->getName())) &&
        "Two completely different attributes are being compared!");
    Assert(
        (this->m_typeId == attribute->getType()) &&
        "Two completely different attributes are being compared!");

    if (attribute->isUndetermind()) {
        LogDebug("Attribute match undetermined");
        return MatchResult::MRUndetermined;
    }

    //Regardles the algorithm used, if we have empty
    //bag the result is always false
    if (this->isValueEmpty() || attribute->isValueEmpty()) {
        if (this->isValueEmpty()) {
            LogDebug("empty bag in condition comparing");
        }
        if (attribute->isValueEmpty()) {
            LogDebug("empty bag in attribute comparing");
        }
        return MatchResult::MRFalse;
    }

    if (this->matchFunction == Match::Equal) {
        return lists_comparator(&(this->value),
                                attribute->getValue(),
                                equal_comparator);
    } else if (this->matchFunction == Match::Glob) {
        return lists_comparator(&(this->value),
                                attribute->getValue(),
                                glob_comparator);
    } else if (this->matchFunction == Match::Regexp) {
        return lists_comparator(&(this->value),
                                attribute->getValue(),
                                regexp_comparator);
    }        //[CR] Change to Assert
    Assert(false && " ** Critical :: no match function selected!");
    return MatchResult::MRFalse; // to remove compilator warning
}

void Attribute::addValue(const std::string *val)
{
    this->getValue()->push_back(*val);
}

std::ostream & operator<<(std::ostream & out,
                          const Attribute & attr)
{
    out << "attr: m_name: " << *(attr.getName())
        << " type: " << Attribute::typeToString(attr.getType())
        << " value: ";
    if (attr.m_undetermindState) {
        out << "Undetermined";
    } else if (attr.getValue()->empty()) {
        out << "Empty string bag";
    } else {
        FOREACH (it, *attr.getValue()) {
            out << *it;
        }
    }
    return out;
}

bool
Attribute::parse(const std::string *input,
                 std::string *val) const
{
    static const char *pattern =
        "^(([^:/?#]+):)?(//([^/?#]*))?([^?#]*)(\\?([^#]*))?(#(.*))?";
    pcrecpp::RE re(pattern);
    re.FullMatch(input->c_str(), &val[0], &val[1],
                 &val[2], &val[3], &val[4],
                 &val[5], &val[6], &val[7], &val[8]);

#ifdef ALL_LOGS
    for (int i = 0; i < 9; i++) {
        LogDebug("val " << i << " :" << val[i]);
    }
#endif

    if (find_error(val)) {
        LogDebug("Input is not an URI " << *input);
        for (int i = 0; i < 9; ++i) {
            val[i].clear();
        }
        return false;
    }

    return true;
}

Attribute::~Attribute()
{
}

std::string * Attribute::uriScheme(const std::string *input) const
{
    std::string part[9];
    if (!parse(input, part)) {
        return NULL;
    }
    return new string(part[1]);
}

std::string *
Attribute::uriAuthority(const std::string *input) const
{
    std::string part[9];
    if (!parse(input, part)) {
        return NULL;
    }
    return new string(part[3]);
}

std::string *
Attribute::uriSchemeAuthority(const std::string *input) const
{
    std::string part[9];
    if (!parse(input, part)) {
        return NULL;
    }

    if (part[0].size() == 0 || part[2].size() == 0) {
        return new std::string();
    }
    return new string(part[0] + part[2]);
}

std::string *
Attribute::uriHost(const std::string *input) const
{
    std::string part[9];
    if (!parse(input, part)) {
        return NULL;
    }
    return getHost(&(part[3]));
}

std::string *
Attribute::uriPath(const std::string *input) const
{
    //TODO right now uriPath leaves leading '/' in uri, this slash is removed from the string
    //it's not clear if leading '/' is a part of path component or only the separator
    std::string part[9];
    if (!parse(input, part)) {
        return NULL;
    }

    std::string * temp = NULL;

    if (part[4].at(0) == '/') {
        temp = new string(part[4].substr(1, part[4].length() - 1));
    } else {
        temp = new string(part[4]);
    }

    return temp;
}

bool Attribute::find_error(const std::string *tab) const
{
    //We are checking tab[1] which contains scheme without ':' at the end
    if (!checkScheme(&(tab[1]))) {
        LogDebug("Check scheme failed, URI is invalid");
        return true; //error found
    }
    if (!checkAuthority(&(tab[3]))) {
        LogDebug("Check authority failed, URI is invalid");
        return true; //error found
    }

    if (!checkPath(&(tab[4]))) {
        LogDebug("Check path failed, URI is invalid");
        return true; //error found
    }

    return false;
}

bool Attribute::checkScheme(const std::string *part) const
{
    Assert(part != NULL && "Checking NULLable string. This should never happen");

    bool result = true;

    //TODO change part->at to data=part->c_str()
    //TODO can scheme be empty? In absolute URI no, in relative URI yes
    if (part->empty()) {
        //Empty string is a correct schema
        result = true;
    } else if (alpha[(int) (part->at(0))] == 0) {
        result = false; // First scheme character must be alpha
    } else {
        // rest must be alpha or digit or '+' or '-' or '.'
        for (unsigned int i = 1; i < part->size(); ++i) {
            int c = static_cast<int>(part->at(i));
            if (!isSchemeAllowedCharacter(c)) {
                result = false;
                break;
            }
        }
    }
    return result;
}

bool Attribute::checkAuthority(const std::string *part) const
{
    Assert(part != NULL && "Checking NULLable string. This should never happen");

    //Server is a subset of reg_m_names so here we only check if authority matches reg_m_name
    //Additional check if authority is a valid 'server' component is done in getHost
    if (part->empty()) {
        return true; //empty authority is valid uri
    }
    bool result = true;

    const char * data = part->c_str();
    for (size_t i = 0; i < part->length(); ++i) {
        int c = (int) data[i];
        if (isUnreserved(c)) {
            continue;
        }
        if (c == '$') {
            continue;
        }
        if (c == ',') {
            continue;
        }
        if (c == ';') {
            continue;
        }
        if (c == ':') {
            continue;
        }
        if (c == '@') {
            continue;
        }
        if (c == '&') {
            continue;
        }
        if (c == '=') {
            continue;
        }
        if (c == '+') {
            continue;
        }
        if (c == '%') {
            if (isEscaped(data + i)) {
                i += 2; //rewind the two escaped characters
                continue;
            }
        }
        result = false;
        break;
    }

    return result;
}

std::string * Attribute::getHost(const std::string *part) const
{
    if (part->empty()) {
        return new std::string("");
    }

    //Check userinfo
    size_t userInfoPos = part->find("@");
    if (userInfoPos != std::string::npos) {
        std::string data = part->substr(0, userInfoPos);
        if (!isUserInfoAllowedString(&data)) {
            return new string(""); //the authority is not composed of 'server'  part
        }
    }

    std::string host;
    //If we use host modifier then authority is composed of 'server' part so
    //the port must contain only digits
    size_t portPos = part->find(":");
    if (portPos != std::string::npos) {
        for (unsigned int i = portPos + 1; i < part->size(); ++i) {
            if (!digit[(int) part->at(i)]) {
                return new string(""); //the authority is not composed of 'server'  part
            }
        }
        host = part->substr(userInfoPos + 1, portPos - (userInfoPos + 1));
    } else {
        host = part->substr(userInfoPos + 1, part->length() - (userInfoPos + 1));
    }

    if (!isHostAllowedString(&host)) {
        //Even if the string is not allowed for host this can still be a valid uri
        return new string("");
    }

    return new std::string(host);
}

bool Attribute::checkPath(const std::string *part) const
{
    bool result = true;

    const char * data = part->c_str();

    for (unsigned int i = 0; i < part->size(); ++i) {
        int c = data[i];
        if (c == '/') {
            //If we found slash then the next character must be a part of segment
            //It cannot be '/' so we have to check it immediately
            i++;
            c = data[i];
            if (!isSegmentAllowedCharacter(c)) {
                result = false;
                break;
            }
        } else if (c == ';') {
            //Start param part of segment
            i++; //Param can be empty so we don't have to check what's right after semicolon
            continue;
        } else if (c == '%') {
            //We have to handle escaped characters differently than other segment allowed characters
            //because we need an array
            if (isEscaped(data + i)) {
                i += 2;
            } else {
                result = false;
                break;
            }
        } else {
            if (!isSegmentAllowedCharacter(c)) {
                result = false;
                break;
            }
        }
    }

    return result;
}

bool Attribute::isSchemeAllowedCharacter(int c) const
{
    bool result = false;
    if (isAlphanum(c)) {
        result = true;
    } else if (c == '+') {
        result = true;
    } else if (c == '-') {
        result = true;
    } else if (c == '.') {
        result = true;
    }

    return result;
}

bool Attribute::isSegmentAllowedCharacter(int c) const
{
    bool result = true;

    //    LogDebug("Checking is segment allowed for char "<<(char)c);

    if (isUnreserved(c)) { //do nothing, result = true
    } else if (c == ':') { //do nothing, result = true
    } else if (c == '@') { //do nothing, result = true
    } else if (c == '&') { //do nothing, result = true
    } else if (c == '=') { //do nothing, result = true
    } else if (c == '+') { //do nothing, result = true
    } else if (c == '$') { //do nothing, result = true
    } else if (c == ',') { //do nothing, result = true
    } else {
        result = false;
    }

    return result;
}

bool Attribute::isUserInfoAllowedString(const std::string * str) const
{
    bool result = false;

    const char * data = str->c_str();

    for (unsigned int i = 0; i < str->length(); ++i) {
        int c = data[i];
        if (isUnreserved(c)) {
            result = true;
        } else if (c == '%') {
            //isEsacped method checks if we don't cross array bounds, so we can
            //safely give data[i] here
            result = isEscaped((data + i));
            if (result == false) {
                break;
            }
            i += 2; //rewind the next two characters sEsacped method checks if we don't cross array bounds, so we can safely rewind
        } else if (c == ',') {
            result = true;
        } else if (c == '$') {
            result = true;
        } else if (c == '+') {
            result = true;
        } else if (c == '=') {
            result = true;
        } else if (c == '&') {
            result = true;
        } else if (c == '@') {
            result = true;
        } else if (c == ':') {
            result = true;
        }
    }
    return result;
}

bool Attribute::isUnreserved(int c) const
{
    return isAlphanum(c) || mark[c];
}

bool Attribute::isAlphanum(int c) const
{
    return alpha[c] || digit[c];
}

bool Attribute::isHex(int c) const
{
    bool result = false;

    if (digit[c]) {
        result = true;
    } else if (c == 'A') {
        result = true;
    } else if (c == 'B') {
        result = true;
    } else if (c == 'C') {
        result = true;
    } else if (c == 'D') {
        result = true;
    } else if (c == 'E') {
        result = true;
    } else if (c == 'F') {
        result = true;
    } else if (c == 'a') {
        result = true;
    } else if (c == 'b') {
        result = true;
    } else if (c == 'c') {
        result = true;
    } else if (c == 'd') {
        result = true;
    } else if (c == 'e') {
        result = true;
    } else if (c == 'f') {
        result = true;
    }

    return result;
}

bool Attribute::isEscaped(const char esc[3]) const
{
    if (esc == NULL) {
        return false;
    }

    if ((esc[0] == 0) || (esc[1] == 0) || (esc[2] == 0)) {
        //We get an array that seems to be out of bounds.
        //To be on the safe side return here
        LogDebug("HEX NULLS");
        return false;
    }

    if (esc[0] != '%') {
        LogDebug(
            "Error: first character of escaped value must be a precent but is "
            <<
            esc[0]);
        return false;
    }

#ifdef ALL_LOGS
    for (int i = 0; i < 3; i++) {
        LogDebug("HEX " << esc[i]);
    }
#endif
    return isHex((int) esc[1]) && isHex((int) esc[2]);
}

bool Attribute::isHostAllowedString(const std::string * str) const
{
    bool result = true;

    if (digit[(int) str->at(0)]) {
        //IPv4 address
        result = isIPv4AllowedString(str);
    } else {
        //Hostname
        result = isHostNameAllowedString(str);
    }

    return result;
}

bool Attribute::isIPv4AllowedString(const std::string * str) const
{
    LogDebug("Is hostIPv4 allowed String for " << *str);

    const char * data = str->c_str();
    bool result = true;
    int digitCounter = 0;
    int dotCounter = 0;

    for (unsigned int i = 0; i < str->length(); ++i) {
        if (data[i] == '.') {
            dotCounter++;
            digitCounter = 0;
        } else if (digit[(int) data[i]]) {
            digitCounter++;
            if ((digitCounter > 3) || !digitCounter) {
                result = false;
                break;
            }
        } else {
            result = false;
            break;
        }
    }
    if (dotCounter != 3) {
        result = false;
    }
    return result;
}

bool Attribute::isHostNameAllowedString(const std::string * str) const
{
    LogDebug("Is hostname allowed String for " << *str);

    int lastPosition = 0; //the position of last dot + 1
    const char * data = str->c_str();
    bool finalDot = false;
    size_t end = str->length();
    bool result = false;

    for (size_t i = 0; i < end; ++i) {
        if (data[i] == '.') {
            if (i == str->length() - 1) { //ending dot
                //There can be a leading '.' int the hostm_name
                finalDot = true;
                break;
            } else {
                //we found domain label
                if (!isDomainLabelAllowedString(data + lastPosition, i -
                                                lastPosition)) {
                    result = false;
                    goto end;
                }
                lastPosition = i + 1; //Set position to position of last dot + 1
            }
        }
    }

    if (finalDot) {
        //we have to rewind one position to check the rightmost string
        //but only in case we find final dot
        end--;
    }
    //Compare only the rightmost string aaa.bbbb.rightmostString.
    result = isTopLabelAllowedString(data + lastPosition, end - lastPosition);

end:

    if (result) {
        LogInfo("Hostname is allowed");
    } else {
        LogInfo("Hostname is NOT allowed");
    }

    return result;
}

bool Attribute::isDomainLabelAllowedString(const char * data,
        int length) const
{
    LogDebug(
        "Is domain allowed String for " << data << " taking first " <<
        length <<
        " chars");

    if (!isAlphanum((int) data[0]) || !isAlphanum((int) data[length - 1])) {
        return false;
    }

    for (int i = 0; i < length; i++) {
        if ((!isAlphanum(data[i])) && !(data[i] == '-')) {
            return false;
        }
    }
    return true;
}

bool Attribute::isTopLabelAllowedString(const char * data,
        int length) const
{
    if ((!alpha[(int) data[0]]) || (!isAlphanum((int) data[length - 1]))) {
        return false;
    }

    for (int i = 1; i < length - 1; i++) {
        if ((!isAlphanum(data[i])) && !(data[i] == '-')) {
            return false;
        }
    }
    return true;
}

void printAttributes(const AttributeSet& attrs)
{
    if (attrs.empty()) {
        LogWarning("Empty attribute set");
    } else {
        LogDebug("PRINT ATTRIBUTES:");
        for (AttributeSet::const_iterator it = attrs.begin();
             it != attrs.end();
             ++it)
        {
            LogDebug("name: " << *(*it)->getName());
        }
    }
}

void printAttributes(const std::list<Attribute> & attrs)
{
    if (attrs.empty()) {
        LogWarning("Empty attribute set");
    } else {
        LogDebug("PRINT ATTRIBUTES:");
        for (std::list<Attribute>::const_iterator it = attrs.begin();
             it != attrs.end();
             ++it
             ) {
            LogDebug(*it);
        }
    }
}

//KW const char * matchResultToString(Attribute::MatchResult result){
//KW
//KW     const char * ret = NULL;
//KW
//KW     switch(result){
//KW
//KW         case Attribute::MRTrue:
//KW             ret = "true";
//KW             break;
//KW         case Attribute::MRFalse:
//KW             ret = "false";
//KW            break;
//KW         case Attribute::MRUndetermined:
//KW             ret = "undetermined";
//KW             break;
//KW         default:
//KW             ret = "Wrong match result";
//KW     }
//KW
//KW     return ret;
//KW
//KW }
