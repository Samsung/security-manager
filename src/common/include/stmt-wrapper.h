/*
 *  Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd All Rights Reserved
 *
 *  Contact: Rafal Krypa <r.krypa@samsung.com>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License
 */
/*
 * @file        stmt-wrapper.h
 * @author      Zofia Abramowska <z.abramowska@samsung.com>
 * @version     1.0
 * @brief       Definition of Statement Wrapper class.
 */

#pragma once

#include <string>
#include <dpl/db/sql_connection.h>

namespace SecurityManager {

class StmtWrapper {
public:
    StmtWrapper(DB::SqlConnection::DataCommand &command) : m_command(command) {}
    DB::SqlConnection::DataCommand &operator->() {
        return *m_command;
    }
    ~StmtWrapper() {
        m_command->Reset();
    }
private:
    DB::SqlConnection::DataCommandAutoPtr &m_command;

};

} /* namespace SecurityManager */
