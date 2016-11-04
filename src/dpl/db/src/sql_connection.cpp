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
/*
 * @file        sql_connection.cpp
 * @author      Przemyslaw Dobrowolski (p.dobrowolsk@samsung.com)
 * @version     1.0
 * @brief       This file is the implementation file of SQL connection
 */
#include <stddef.h>
#include <dpl/db/sql_connection.h>
#include <dpl/db/naive_synchronization_object.h>
#include <dpl/free_deleter.h>
#include <memory>
#include <dpl/noncopyable.h>
#include <dpl/assert.h>
#include <db-util.h>
#include <unistd.h>
#include <cstdio>
#include <cstdarg>

/*
 * If you want to enable logs from this class, pass DB_LOG definition
 * during compilation time
 */
#ifdef DB_LOGS
#define LogDB(msg) LogDebug(msg)
#else
#define LogDB(msg) LogDummy(msg)
#endif

namespace SecurityManager {
namespace DB {
namespace // anonymous
{
class ScopedNotifyAll :
    public Noncopyable
{
  private:
    SqlConnection::SynchronizationObject *m_synchronizationObject;

  public:
    explicit ScopedNotifyAll(
        SqlConnection::SynchronizationObject *synchronizationObject) :
        m_synchronizationObject(synchronizationObject)
    {}

    ~ScopedNotifyAll()
    {
        if (!m_synchronizationObject) {
            return;
        }

        LogDB("Notifying after successful synchronize");
        m_synchronizationObject->NotifyAll();
    }
};
} // namespace anonymous

SqlConnection::DataCommand::DataCommand(SqlConnection *connection,
                                        const char *buffer) :
    m_masterConnection(connection),
    m_stmt(NULL)
{
    Assert(connection != NULL);

    // Notify all after potentially synchronized database connection access
    ScopedNotifyAll notifyAll(connection->m_synchronizationObject.get());

    for (;;) {
        int ret = sqlite3_prepare_v2(connection->m_connection,
                                     buffer, strlen(buffer),
                                     &m_stmt, NULL);

        if (ret == SQLITE_OK) {
            LogDB("Data command prepared successfuly");
            break;
        } else if (ret == SQLITE_BUSY) {
            LogDB("Collision occurred while preparing SQL command");

            // Synchronize if synchronization object is available
            if (connection->m_synchronizationObject) {
                LogDB("Performing synchronization");
                connection->m_synchronizationObject->Synchronize();
                continue;
            }

            // No synchronization object defined. Fail.
        }

        // Fatal error
        const char *error = sqlite3_errmsg(m_masterConnection->m_connection);

        LogDB("SQL prepare data command failed");
        LogDB("    Statement: " << buffer);
        LogDB("    Error: " << error);

        ThrowMsg(Exception::SyntaxError, error);
    }

    LogDB("Prepared data command: " << buffer);

    // Increment stored data command count
    ++m_masterConnection->m_dataCommandsCount;
}

SqlConnection::DataCommand::~DataCommand()
{
    LogDB("SQL data command finalizing");

    if (sqlite3_finalize(m_stmt) != SQLITE_OK) {
        LogDB("Failed to finalize data command");
    }

    // Decrement stored data command count
    --m_masterConnection->m_dataCommandsCount;
}

void SqlConnection::DataCommand::CheckBindResult(int result)
{
    if (result != SQLITE_OK) {
        const char *error = sqlite3_errmsg(
                m_masterConnection->m_connection);

        LogDB("Failed to bind SQL statement parameter");
        LogDB("    Error: " << error);

        ThrowMsg(Exception::SyntaxError, error);
    }
}

void SqlConnection::DataCommand::BindNull(
    SqlConnection::ArgumentIndex position)
{
    CheckBindResult(sqlite3_bind_null(m_stmt, position));
    LogDB("SQL data command bind null: ["
                << position << "]");
}

void SqlConnection::DataCommand::BindInteger(
    SqlConnection::ArgumentIndex position,
    int value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position, value));
    LogDB("SQL data command bind integer: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindInt8(
    SqlConnection::ArgumentIndex position,
    int8_t value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position,
                                     static_cast<int>(value)));
    LogDB("SQL data command bind int8: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindInt16(
    SqlConnection::ArgumentIndex position,
    int16_t value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position,
                                     static_cast<int>(value)));
    LogDB("SQL data command bind int16: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindInt32(
    SqlConnection::ArgumentIndex position,
    int32_t value)
{
    CheckBindResult(sqlite3_bind_int(m_stmt, position,
                                     static_cast<int>(value)));
    LogDB("SQL data command bind int32: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindInt64(
    SqlConnection::ArgumentIndex position,
    int64_t value)
{
    CheckBindResult(sqlite3_bind_int64(m_stmt, position,
                                       static_cast<sqlite3_int64>(value)));
    LogDB("SQL data command bind int64: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindFloat(
    SqlConnection::ArgumentIndex position,
    float value)
{
    CheckBindResult(sqlite3_bind_double(m_stmt, position,
                                        static_cast<double>(value)));
    LogDB("SQL data command bind float: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindDouble(
    SqlConnection::ArgumentIndex position,
    double value)
{
    CheckBindResult(sqlite3_bind_double(m_stmt, position, value));
    LogDB("SQL data command bind double: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindString(
    SqlConnection::ArgumentIndex position,
    const char *value)
{
    if (!value) {
        BindNull(position);
        return;
    }

    // Assume that text may disappear
    CheckBindResult(sqlite3_bind_text(m_stmt, position,
                                      value, strlen(value),
                                      SQLITE_TRANSIENT));

    LogDB("SQL data command bind string: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindString(
        SqlConnection::ArgumentIndex position,
        const std::string& value)
{
    CheckBindResult(sqlite3_bind_text(m_stmt, position,
                                      value.c_str(), value.length(),
                                      SQLITE_TRANSIENT));

    LogDB("SQL data command bind string: ["
                << position << "] -> " << value);
}

void SqlConnection::DataCommand::BindInteger(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInteger(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt8(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int8_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt8(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt16(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int16_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt16(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt32(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int32_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt32(position, *value);
    }
}

void SqlConnection::DataCommand::BindInt64(
    SqlConnection::ArgumentIndex position,
    const boost::optional<int64_t> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindInt64(position, *value);
    }
}

void SqlConnection::DataCommand::BindFloat(
    SqlConnection::ArgumentIndex position,
    const boost::optional<float> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindFloat(position, *value);
    }
}

void SqlConnection::DataCommand::BindDouble(
    SqlConnection::ArgumentIndex position,
    const boost::optional<double> &value)
{
    if (!value) {
        BindNull(position);
    } else {
        BindDouble(position, *value);
    }
}

bool SqlConnection::DataCommand::Step()
{
    // Notify all after potentially synchronized database connection access
    ScopedNotifyAll notifyAll(
        m_masterConnection->m_synchronizationObject.get());

    for (;;) {
        int ret = sqlite3_step(m_stmt);

        if (ret == SQLITE_ROW) {
            LogDB("SQL data command step ROW");
            return true;
        } else if (ret == SQLITE_DONE) {
            LogDB("SQL data command step DONE");
            return false;
        } else if (ret == SQLITE_BUSY) {
            LogDB("Collision occurred while executing SQL command");

            // Synchronize if synchronization object is available
            if (m_masterConnection->m_synchronizationObject) {
                LogDB("Performing synchronization");

                m_masterConnection->
                    m_synchronizationObject->Synchronize();

                continue;
            }

            // No synchronization object defined. Fail.
        }

        // Fatal error
        const char *error = sqlite3_errmsg(m_masterConnection->m_connection);

        LogDB("SQL step data command failed");
        LogDB("    Error: " << error);

        if (ret == SQLITE_CONSTRAINT) {
            ThrowMsg(Exception::ConstraintError, error);
        }
        ThrowMsg(Exception::InternalError, error);
    }
}

void SqlConnection::DataCommand::Reset()
{
    /*
     * According to:
     * http://www.sqlite.org/c3ref/stmt.html
     *
     * if last sqlite3_step command on this stmt returned an error,
     * then sqlite3_reset will return that error, althought it is not an error.
     * So sqlite3_reset allways succedes.
     */
    sqlite3_reset(m_stmt);

    LogDB("SQL data command reset");
}

void SqlConnection::DataCommand::CheckColumnIndex(
    SqlConnection::ColumnIndex column)
{
    if (column < 0 || column >= sqlite3_column_count(m_stmt)) {
        ThrowMsg(Exception::InvalidColumn, "Column index is out of bounds");
    }
}

bool SqlConnection::DataCommand::IsColumnNull(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column type: [" << column << "]");
    CheckColumnIndex(column);
    return sqlite3_column_type(m_stmt, column) == SQLITE_NULL;
}

int SqlConnection::DataCommand::GetColumnInteger(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column integer: [" << column << "]");
    CheckColumnIndex(column);
    int value = sqlite3_column_int(m_stmt, column);
    LogDB("    Value: " << value);
    return value;
}

int8_t SqlConnection::DataCommand::GetColumnInt8(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column int8: [" << column << "]");
    CheckColumnIndex(column);
    int8_t value = static_cast<int8_t>(sqlite3_column_int(m_stmt, column));
    LogDB("    Value: " << value);
    return value;
}

int16_t SqlConnection::DataCommand::GetColumnInt16(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column int16: [" << column << "]");
    CheckColumnIndex(column);
    int16_t value = static_cast<int16_t>(sqlite3_column_int(m_stmt, column));
    LogDB("    Value: " << value);
    return value;
}

int32_t SqlConnection::DataCommand::GetColumnInt32(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column int32: [" << column << "]");
    CheckColumnIndex(column);
    int32_t value = static_cast<int32_t>(sqlite3_column_int(m_stmt, column));
    LogDB("    Value: " << value);
    return value;
}

int64_t SqlConnection::DataCommand::GetColumnInt64(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column int64: [" << column << "]");
    CheckColumnIndex(column);
    int64_t value = static_cast<int64_t>(sqlite3_column_int64(m_stmt, column));
    LogDB("    Value: " << value);
    return value;
}

float SqlConnection::DataCommand::GetColumnFloat(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column float: [" << column << "]");
    CheckColumnIndex(column);
    float value = static_cast<float>(sqlite3_column_double(m_stmt, column));
    LogDB("    Value: " << value);
    return value;
}

double SqlConnection::DataCommand::GetColumnDouble(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column double: [" << column << "]");
    CheckColumnIndex(column);
    double value = sqlite3_column_double(m_stmt, column);
    LogDB("    Value: " << value);
    return value;
}

std::string SqlConnection::DataCommand::GetColumnString(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column string: [" << column << "]");
    CheckColumnIndex(column);

    const char *value = reinterpret_cast<const char *>(
            sqlite3_column_text(m_stmt, column));

    LogDB("Value: " << (value ? value : "NULL"));

    if (value == NULL) {
        return std::string();
    }

    return std::string(value);
}

boost::optional<int> SqlConnection::DataCommand::GetColumnOptionalInteger(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column optional integer: ["
                << column << "]");
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int>();
    }
    int value = sqlite3_column_int(m_stmt, column);
    LogDB("    Value: " << value);
    return boost::optional<int>(value);
}

boost::optional<int8_t> SqlConnection::DataCommand::GetColumnOptionalInt8(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column optional int8: ["
                << column << "]");
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int8_t>();
    }
    int8_t value = static_cast<int8_t>(sqlite3_column_int(m_stmt, column));
    LogDB("    Value: " << value);
    return boost::optional<int8_t>(value);
}

boost::optional<int16_t> SqlConnection::DataCommand::GetColumnOptionalInt16(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column optional int16: ["
                << column << "]");
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int16_t>();
    }
    int16_t value = static_cast<int16_t>(sqlite3_column_int(m_stmt, column));
    LogDB("    Value: " << value);
    return boost::optional<int16_t>(value);
}

boost::optional<int32_t> SqlConnection::DataCommand::GetColumnOptionalInt32(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column optional int32: ["
                << column << "]");
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int32_t>();
    }
    int32_t value = static_cast<int32_t>(sqlite3_column_int(m_stmt, column));
    LogDB("    Value: " << value);
    return boost::optional<int32_t>(value);
}

boost::optional<int64_t> SqlConnection::DataCommand::GetColumnOptionalInt64(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column optional int64: ["
                << column << "]");
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<int64_t>();
    }
    int64_t value = static_cast<int64_t>(sqlite3_column_int64(m_stmt, column));
    LogDB("    Value: " << value);
    return boost::optional<int64_t>(value);
}

boost::optional<float> SqlConnection::DataCommand::GetColumnOptionalFloat(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column optional float: ["
                << column << "]");
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<float>();
    }
    float value = static_cast<float>(sqlite3_column_double(m_stmt, column));
    LogDB("    Value: " << value);
    return boost::optional<float>(value);
}

boost::optional<double> SqlConnection::DataCommand::GetColumnOptionalDouble(
    SqlConnection::ColumnIndex column)
{
    LogDB("SQL data command get column optional double: ["
                << column << "]");
    CheckColumnIndex(column);
    if (sqlite3_column_type(m_stmt, column) == SQLITE_NULL) {
        return boost::optional<double>();
    }
    double value = sqlite3_column_double(m_stmt, column);
    LogDB("    Value: " << value);
    return boost::optional<double>(value);
}

void SqlConnection::Connect(const std::string &address,
                            Flag::Type type,
                            Flag::Option flag)
{
    if (m_connection != NULL) {
        LogDB("Already connected.");
        return;
    }
    LogDB("Connecting to DB: " << address << "...");

    // Connect to database
    int result;
    if (type & Flag::UseLucene) {
        result = db_util_open_with_options(
                address.c_str(),
                &m_connection,
                flag,
                NULL);

        m_usingLucene = true;
        LogDB("Lucene index enabled");
    } else {
        result = sqlite3_open_v2(
                address.c_str(),
                &m_connection,
                flag,
                NULL);

        m_usingLucene = false;
        LogDB("Lucene index disabled");
    }

    if (result == SQLITE_OK) {
        LogDB("Connected to DB");
    } else {
        LogDB("Failed to connect to DB!");
        ThrowMsg(Exception::ConnectionBroken, address);
    }

    // Enable foreign keys
    TurnOnForeignKeys();
}

void SqlConnection::Disconnect()
{
    if (m_connection == NULL) {
        LogDB("Already disconnected.");
        return;
    }

    LogDB("Disconnecting from DB...");

    // All stored data commands must be deleted before disconnect
    AssertMsg(m_dataCommandsCount == 0,
           "All stored procedures must be deleted"
           " before disconnecting SqlConnection");

    int result;

    if (m_usingLucene) {
        result = db_util_close(m_connection);
    } else {
        result = sqlite3_close(m_connection);
    }

    if (result != SQLITE_OK) {
        const char *error = sqlite3_errmsg(m_connection);
        LogDB("SQL close failed");
        LogDB("    Error: " << error);
        Throw(Exception::InternalError);
    }

    m_connection = NULL;

    LogDB("Disconnected from DB");
}

bool SqlConnection::CheckTableExist(const char *tableName)
{
    if (m_connection == NULL) {
        LogDB("Cannot execute command. Not connected to DB!");
        return false;
    }

    DataCommandAutoPtr command =
        PrepareDataCommand("select tbl_name from sqlite_master where name=?;");

    command->BindString(1, tableName);

    if (!command->Step()) {
        LogDB("No matching records in table");
        return false;
    }

    return command->GetColumnString(0) == tableName;
}

SqlConnection::SqlConnection(const std::string &address,
                             Flag::Type flag,
                             Flag::Option option,
                             SynchronizationObject *synchronizationObject) :
    m_connection(NULL),
    m_usingLucene(false),
    m_dataCommandsCount(0),
    m_synchronizationObject(synchronizationObject)
{
    LogDB("Opening database connection to: " << address);

    // Connect to DB
    SqlConnection::Connect(address, flag, option);

    if (!m_synchronizationObject) {
        LogDB("No synchronization object defined");
    }
}

SqlConnection::~SqlConnection()
{
    LogDB("Closing database connection");

    // Disconnect from DB
    Try
    {
        SqlConnection::Disconnect();
    }
    Catch(Exception::Base)
    {
        LogDB("Failed to disconnect from database");
    }
}

void SqlConnection::ExecCommand(const char *format, ...)
{
    if (m_connection == NULL) {
        LogDB("Cannot execute command. Not connected to DB!");
        return;
    }

    if (format == NULL) {
        LogDB("Null query!");
        ThrowMsg(Exception::SyntaxError, "Null statement");
    }

    char *rawBuffer;

    va_list args;
    va_start(args, format);

    if (vasprintf(&rawBuffer, format, args) == -1) {
        rawBuffer = NULL;
    }

    va_end(args);

    std::unique_ptr<char[],free_deleter> buffer(rawBuffer);

    if (!buffer) {
        LogDB("Failed to allocate statement string");
        return;
    }

    LogDB("Executing SQL command: " << buffer.get());

    // Notify all after potentially synchronized database connection access
    ScopedNotifyAll notifyAll(m_synchronizationObject.get());

    for (;;) {
        char *errorBuffer;

        int ret = sqlite3_exec(m_connection,
                               buffer.get(),
                               NULL,
                               NULL,
                               &errorBuffer);

        std::string errorMsg;

        // Take allocated error buffer
        if (errorBuffer != NULL) {
            errorMsg = errorBuffer;
            sqlite3_free(errorBuffer);
        }

        if (ret == SQLITE_OK) {
            return;
        }

        if (ret == SQLITE_BUSY) {
            LogDB("Collision occurred while executing SQL command");

            // Synchronize if synchronization object is available
            if (m_synchronizationObject) {
                LogDB("Performing synchronization");
                m_synchronizationObject->Synchronize();
                continue;
            }

            // No synchronization object defined. Fail.
        }

        // Fatal error
        LogDB("Failed to execute SQL command. Error: " << errorMsg);
        ThrowMsg(Exception::SyntaxError, errorMsg);
    }
}

SqlConnection::DataCommandAutoPtr SqlConnection::PrepareDataCommand(
    const char *format,
    ...)
{
    if (m_connection == NULL) {
        LogDB("Cannot execute data command. Not connected to DB!");
        return DataCommandAutoPtr();
    }

    char *rawBuffer;

    va_list args;
    va_start(args, format);

    if (vasprintf(&rawBuffer, format, args) == -1) {
        rawBuffer = NULL;
    }

    va_end(args);

    std::unique_ptr<char[],free_deleter> buffer(rawBuffer);

    if (!buffer) {
        LogDB("Failed to allocate statement string");
        return DataCommandAutoPtr();
    }

    LogDB("Executing SQL data command: " << buffer.get());

    return DataCommandAutoPtr(new DataCommand(this, buffer.get()));
}

SqlConnection::RowID SqlConnection::GetLastInsertRowID() const
{
    return static_cast<RowID>(sqlite3_last_insert_rowid(m_connection));
}

void SqlConnection::TurnOnForeignKeys()
{
    ExecCommand("PRAGMA foreign_keys = ON;");
}

void SqlConnection::BeginTransaction()
{
    ExecCommand("BEGIN;");
}

void SqlConnection::RollbackTransaction()
{
    ExecCommand("ROLLBACK;");
}

void SqlConnection::CommitTransaction()
{
    ExecCommand("COMMIT;");
}

SqlConnection::SynchronizationObject *
SqlConnection::AllocDefaultSynchronizationObject()
{
    return new NaiveSynchronizationObject();
}
} // namespace DB
} // namespace SecurityManager
