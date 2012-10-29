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
#include <ace/TreeNode.h>
#include <dpl/assert.h>
#include <dpl/log/log.h>

//Tree node destructor is a tricky part, only the original tree should remove the elements
//release resources should be called when we want to destroy the whole tree
TreeNode::~TreeNode()
{
}

//TODO release resources is releaseTheSubtree and delete the element
void TreeNode::releaseResources()
{
    Assert(this != 0);
    delete element;
    std::list<TreeNode*>::iterator it = this->children.begin();
    while (it != children.end()) {
        (*it)->releaseResources();
        ++it;
    }
    delete this;
}

int TreeNode::level = 0;

std::ostream & operator<<(std::ostream & out,
        const TreeNode * node)
{
    std::string tmp;

    switch (node->getTypeID()) {
    case TreeNode::Policy:
        tmp = "Policy";
        break;
    case TreeNode::PolicySet:
        tmp = "PolicySet";
        break;
    case TreeNode::Rule:
        tmp = "Rule";
        break;
    default:
        break;
    }

    out << "" << tmp << "-> children count: " << node->children.size() <<
    ": " << std::endl;
    AbstractTreeElement * el = node->getElement();
    if (el != NULL) {
        el->printData();
    } else {
        std::cout << "Empty element!" << std::endl;
    }

    return out;
}

