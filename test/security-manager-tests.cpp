/*
 * Copyright (c) 2016 Samsung Electronics Co., Ltd All Rights Reserved
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
 * @file        test/security-manager-tests.cpp
 * @author      Radoslaw Bartosiak <r.bartosiak@samsung.com>
 * @version     1.0
 * @brief       Security manager tests
 */

#include <iostream>
#include <boost/test/unit_test.hpp>
#include <boost/test/unit_test_log.hpp>
#include <boost/test/results_reporter.hpp>
#include <colour_log_formatter.h>
#include <dpl/log/log.h>

struct TestConfig {
    TestConfig()
    {
        boost::unit_test::unit_test_log.set_threshold_level(
            boost::unit_test::log_test_units);
        boost::unit_test::results_reporter::set_level(boost::unit_test::SHORT_REPORT);
        boost::unit_test::unit_test_log.set_formatter(new SecurityManager::colour_log_formatter);
    }
    ~TestConfig()
    {
    }
};


struct LogSetup {
    LogSetup()
    {
        SecurityManager::Singleton<SecurityManager::Log::LogSystem>::Instance().SetTag("SECURITY_MANAGER_TESTS");
    }
    ~LogSetup() {}
};

BOOST_GLOBAL_FIXTURE(TestConfig)
BOOST_GLOBAL_FIXTURE(LogSetup)
