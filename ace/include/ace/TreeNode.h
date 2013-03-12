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
//  @ File Name : TreeNode.h
//  @ Date : 2009-05-06
//  @ Author : Samsung
//
//

#ifndef _TREE_NODE_H
#define _TREE_NODE_H

#include <iostream>
#include <list>

#include <ace/AbstractTreeElement.h>

class TreeNode;

typedef std::list<TreeNode *> ChildrenSet;
typedef std::list<TreeNode *>::iterator ChildrenIterator;
typedef std::list<TreeNode *>::const_iterator ChildrenConstIterator;

class TreeNode
{
  public:
    //TODO nazwac pozadnie TYPY - moze jakas konwencja ... ??!!
    enum TypeID { Policy =0, PolicySet=1, Rule=2};

    const ChildrenSet  & getChildrenSet() const
    {
        return children;
    }

    TreeNode * getParent() const
    {
        return this->parent;
    }

    void setParent(TreeNode *parent)
    {
        this->parent = parent;
    }

    TypeID getTypeID() const
    {
        return this->typeID;
    }

    void addChild(TreeNode *child)
    {
        child->setParent(this);
        children.push_back(child);
    }

    /**
     * Clone the node
     */
    // KW        TreeNode * clone() { return new TreeNode(NULL,this->getTypeID(),this->getElement()); }

    TreeNode(TreeNode * parent,
            TypeID type,
            AbstractTreeElement * element) :
        parent(parent),
        typeID(type),
        element(element)
    {
    }

    AbstractTreeElement * getElement() const
    {
        return element;
    }

  private:
    virtual ~TreeNode();

  public:
    /*
     * It is common that we create a copy of tree structure created out of xml file. However we don't want to
     * copy abstract elements ( Policies and Rules ) because we need them only for reading. We want to modify the
     * tree structure though. Therefore we copy TreeNode. When the copy of the original tree is being destroyed method
     * releaseTheSubtree should be called on "root". It automatically traverse the tree and call TreeNode destructors for
     * each TreeNode in the tree. It doesn't remove the abstract elements in the tree ( there is always at most one abstract
     * element instance, when tree is copied it is a shallow copy.
     * When we want to completely get rid of the the tree and abstract elements we have to call releaseResources on tree root.
     * We may want to do this for instance when we want to serialize the tree to disc. releaseResource method traverses the tree
     * and releses the resources, as well as the TreeNode so NO releaseTheSubtree is required any more
     */
    void releaseResources();

    /**
     * Used to delete the copies of tree structure. The original tree structure should be removed with releaseResources method.
     * ReleaseTheSubtree method doesn't delete the abstract elements, only TreeNodes. It traverses the whole tree, so it should be
     * called on behalf of root of the tree
     */
    // KW        void releaseTheSubtree();

    friend std::ostream & operator<<(std::ostream & out,
            const TreeNode * node);
    // KW        void printSubtree();

  private:
    // KW    TreeNode(const TreeNode& pattern){ (void)pattern; }

    std::list<TreeNode *> children;
    TreeNode * parent;
    //TODO standarize ID case
    TypeID typeID;
    AbstractTreeElement * element;
    static int level;
};

#endif  //_TREE_NODE_H
