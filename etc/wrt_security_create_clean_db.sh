#!/bin/sh
# Copyright (c) 2011 Samsung Electronics Co., Ltd All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.
#
for name in ace
do
    rm -f /opt/dbspace/.$name.db
    rm -f /opt/dbspace/.$name.db-journal
    SQL="PRAGMA journal_mode = PERSIST;"
    sqlite3 /opt/dbspace/.$name.db "$SQL"
    SQL=".read /usr/share/wrt-engine/"$name"_db.sql"
    sqlite3 /opt/dbspace/.$name.db "$SQL"
    touch /opt/dbspace/.$name.db-journal
    chown 0:6026 /opt/dbspace/.$name.db
    chown 0:6026 /opt/dbspace/.$name.db-journal
    chmod 660 /opt/dbspace/.$name.db
    chmod 660 /opt/dbspace/.$name.db-journal
done


