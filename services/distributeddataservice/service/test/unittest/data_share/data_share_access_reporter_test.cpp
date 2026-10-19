/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#define LOG_TAG "DataShareAccessReporterTest"

#include <gtest/gtest.h>

#include <string>

#include "hiview_adapter.h"
#include "log_print.h"

using namespace testing::ext;
using namespace OHOS::DataShare;

namespace OHOS::Test {
class DataShareAccessReporterTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp() {};
    void TearDown() {};
};

namespace {
const std::string TEST_URI = "datashare:///com.example.provider/store/table";
const std::string PROVIDER_NAME = "com.example.provider";
const std::string CALLER_NAME = "com.example.caller";
constexpr uint32_t FUNC_ID_QUERY = 1;
constexpr uint32_t FUNC_ID_INSERT = 2;
// Same value as MAX_KEY_COUNT defined in hiview_adapter.cpp
constexpr uint32_t MAX_KEY_COUNT_FOR_TEST = 5000;
} // namespace

/**
 * @tc.name: GetInstance_ReturnsSameInstance
 * @tc.desc: test DataShareAccessReporter GetInstance returns the same singleton instance
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, GetInstance_ReturnsSameInstance, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::GetInstance_ReturnsSameInstance start");
    auto &instance1 = DataShareAccessReporter::GetInstance();
    auto &instance2 = DataShareAccessReporter::GetInstance();
    EXPECT_EQ(&instance1, &instance2);
    ZLOGI("DataShareAccessReporterTest::GetInstance_ReturnsSameInstance end");
}

/**
 * @tc.name: Record_SameKeyMultipleTimes_AggregatesCount
 * @tc.desc: test Record aggregates call count for the same uri/provider/caller/funcId key
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_SameKeyMultipleTimes_AggregatesCount, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_SameKeyMultipleTimes_AggregatesCount start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    for (uint32_t i = 0; i < 5; i++) {
        EXPECT_NO_FATAL_FAILURE(
            reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24));
    }
    EXPECT_EQ(reporter.GetStatsCount(), 1U);
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.count, 5U);
    EXPECT_EQ(info.uri, TEST_URI);
    EXPECT_EQ(info.providerBundleName, PROVIDER_NAME);
    EXPECT_EQ(info.callerBundleName, CALLER_NAME);
    EXPECT_EQ(info.funcId, FUNC_ID_QUERY);
    ZLOGI("DataShareAccessReporterTest::Record_SameKeyMultipleTimes_AggregatesCount end");
}

/**
 * @tc.name: Record_DifferentFuncId_CreatesSeparateEntry
 * @tc.desc: test Record with a different funcId creates a separate statistics entry
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_DifferentFuncId_CreatesSeparateEntry, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_DifferentFuncId_CreatesSeparateEntry start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_INSERT, 24);
    EXPECT_EQ(reporter.GetStatsCount(), 2U);
    AccessStatInfo queryInfo;
    AccessStatInfo insertInfo;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, queryInfo));
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_INSERT, insertInfo));
    EXPECT_EQ(queryInfo.count, 1U);
    EXPECT_EQ(insertInfo.count, 1U);
    ZLOGI("DataShareAccessReporterTest::Record_DifferentFuncId_CreatesSeparateEntry end");
}

/**
 * @tc.name: FlushAll_AggregatedStats_FlushesAll
 * @tc.desc: test FlushAll flushes all aggregated stats regardless of due time
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, FlushAll_AggregatedStats_FlushesAll, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::FlushAll_AggregatedStats_FlushesAll start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    EXPECT_EQ(reporter.GetStatsCount(), 1U);
    EXPECT_NO_FATAL_FAILURE(reporter.FlushAll());
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    AccessStatInfo info;
    EXPECT_FALSE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    ZLOGI("DataShareAccessReporterTest::FlushAll_AggregatedStats_FlushesAll end");
}

/**
 * @tc.name: InvokeData_NotDueStats_KeepsEntries
 * @tc.desc: test InvokeData keeps entries whose report interval has not elapsed
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, InvokeData_NotDueStats_KeepsEntries, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::InvokeData_NotDueStats_KeepsEntries start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    EXPECT_NO_FATAL_FAILURE(reporter.InvokeData());
    EXPECT_EQ(reporter.GetStatsCount(), 1U);
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.count, 1U);
    reporter.FlushAll();
    ZLOGI("DataShareAccessReporterTest::InvokeData_NotDueStats_KeepsEntries end");
}

/**
 * @tc.name: Record_DifferentProviders_KeepOwnIntervals
 * @tc.desc: test each provider entry keeps its own report interval without overriding others
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_DifferentProviders_KeepOwnIntervals, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_DifferentProviders_KeepOwnIntervals start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 1);
    reporter.Record("datashare://com.example.other/store/table", "com.example.other", CALLER_NAME,
        FUNC_ID_QUERY, 48);
    AccessStatInfo first;
    AccessStatInfo second;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, first));
    EXPECT_TRUE(reporter.GetAccessStatInfo("datashare://com.example.other/store/table", "com.example.other",
        CALLER_NAME, FUNC_ID_QUERY, second));
    EXPECT_EQ(first.reportIntervalHours, 1);
    EXPECT_EQ(second.reportIntervalHours, 48);
    EXPECT_GT(first.windowStartTime, 0);
    EXPECT_GT(second.windowStartTime, 0);
    reporter.FlushAll();
    ZLOGI("DataShareAccessReporterTest::Record_DifferentProviders_KeepOwnIntervals end");
}

/**
 * @tc.name: Record_SameKeyInterval_LatestConfigWins
 * @tc.desc: test Record updates the entry interval to the latest configuration of the same key
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_SameKeyInterval_LatestConfigWins, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_SameKeyInterval_LatestConfigWins start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 48);
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 2);
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.reportIntervalHours, 2);
    EXPECT_EQ(info.count, 2U);
    reporter.FlushAll();
    ZLOGI("DataShareAccessReporterTest::Record_SameKeyInterval_LatestConfigWins end");
}

/**
 * @tc.name: Record_InvalidInterval_KeepsEntryInterval
 * @tc.desc: test Record with interval below the minimum keeps the entry interval unchanged
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_InvalidInterval_KeepsEntryInterval, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_InvalidInterval_KeepsEntryInterval start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    EXPECT_NO_FATAL_FAILURE(reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 0));
    EXPECT_NO_FATAL_FAILURE(reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, -1));
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.reportIntervalHours, 24);
    reporter.FlushAll();
    ZLOGI("DataShareAccessReporterTest::Record_InvalidInterval_KeepsEntryInterval end");
}

/**
 * @tc.name: Record_ExceedsMaxKeyCount_TriggersImmediateFlush
 * @tc.desc: test Record beyond the max key count triggers an immediate flush without executor
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_ExceedsMaxKeyCount_TriggersImmediateFlush, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_ExceedsMaxKeyCount_TriggersImmediateFlush start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    for (uint32_t i = 0; i <= MAX_KEY_COUNT_FOR_TEST; i++) {
        std::string uri = TEST_URI + "/" + std::to_string(i);
        reporter.Record(uri, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    }
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    ZLOGI("DataShareAccessReporterTest::Record_ExceedsMaxKeyCount_TriggersImmediateFlush end");
}

/**
 * @tc.name: Init_NullptrExecutor_NoFatal
 * @tc.desc: test Init with nullptr executor does not crash
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Init_NullptrExecutor_NoFatal, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Init_NullptrExecutor_NoFatal start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    EXPECT_NO_FATAL_FAILURE(reporter.Init(nullptr));
    ZLOGI("DataShareAccessReporterTest::Init_NullptrExecutor_NoFatal end");
}

/**
 * @tc.name: InvokeData_EmptyStats_NoFatal
 * @tc.desc: test InvokeData with empty stats does not crash
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, InvokeData_EmptyStats_NoFatal, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::InvokeData_EmptyStats_NoFatal start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    EXPECT_NO_FATAL_FAILURE(reporter.InvokeData());
    ZLOGI("DataShareAccessReporterTest::InvokeData_EmptyStats_NoFatal end");
}
/**
 * @tc.name: AnonymousUri_LongPath_KeepsBundleNameAndTail
 * @tc.desc: test AnonymousUri keeps bundleName and last 10 chars of the rest without scheme prefix
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, AnonymousUri_LongPath_KeepsBundleNameAndTail, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_LongPath_KeepsBundleNameAndTail start");
    std::string uri = "datashare://com.example.provider/aaaabbbbccccdddd";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(uri), "com.example.provider******bbccccdddd");
    std::string longUri = "datashare://com.example.provider/store/table_weather";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(longUri), "com.example.provider******le_weather");
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_LongPath_KeepsBundleNameAndTail end");
}

/**
 * @tc.name: AnonymousUri_ShortPath_ReturnsBundleNameAndPath
 * @tc.desc: test AnonymousUri returns bundleName and original path when the path is not longer than 10 chars
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, AnonymousUri_ShortPath_ReturnsBundleNameAndPath, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_ShortPath_ReturnsBundleNameAndPath start");
    std::string uri = "datashare://com.example.provider/tbl";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(uri), "com.example.provider/tbl");
    std::string uriWithoutPath = "datashare://com.example.provider";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(uriWithoutPath), "com.example.provider");
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_ShortPath_ReturnsBundleNameAndPath end");
}

/**
 * @tc.name: AnonymousUri_NoScheme_FallsBackToDefaultAnonymous
 * @tc.desc: test AnonymousUri falls back to URIUtils::Anonymous for uri without scheme
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, AnonymousUri_NoScheme_FallsBackToDefaultAnonymous, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_NoScheme_FallsBackToDefaultAnonymous start");
    std::string uri = "abcdefghijklmnopqrstuvwxyz";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(uri), "******qrstuvwxyz");
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_NoScheme_FallsBackToDefaultAnonymous end");
}

/**
 * @tc.name: Record_UsesAnonymousUriKey_KeepsBundleNamePrefix
 * @tc.desc: test Record aggregates keys with the bundleName prefix kept by AnonymousUri
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_UsesAnonymousUriKey_KeepsBundleNamePrefix, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_UsesAnonymousUriKey_KeepsBundleNamePrefix start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record("datashare://com.example.provider/aaaabbbbccccdddd", PROVIDER_NAME, CALLER_NAME,
        FUNC_ID_QUERY, 24);
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo("datashare://com.example.provider/aaaabbbbccccdddd", PROVIDER_NAME,
        CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.count, 1U);
    ZLOGI("DataShareAccessReporterTest::Record_UsesAnonymousUriKey_KeepsBundleNamePrefix end");
}
} // namespace OHOS::Test
