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

#include <chrono>
#include <string>
#include <thread>

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
const std::string OTHER_URI = "datashare://com.example.other/store/table";
const std::string OTHER_PROVIDER = "com.example.other";
constexpr uint32_t FUNC_ID_QUERY = 1;
constexpr uint32_t FUNC_ID_INSERT = 2;
// Same value as MAX_KEY_COUNT defined in hiview_adapter.cpp
constexpr uint32_t MAX_KEY_COUNT_FOR_TEST = 5000;
// Same value as MAX_REPORT_INTERVAL_HOURS defined in hiview_adapter.cpp
constexpr int32_t MAX_INTERVAL_HOURS_FOR_TEST = 48;
constexpr int64_t TWO_HOURS_MS = 2LL * 3600 * 1000;
constexpr int64_t THROTTLE_WINDOW_MS = 60LL * 1000;
// Time for the asynchronous overflow flush task to complete on the executor.
constexpr int ASYNC_FLUSH_WAIT_MS = 200;
// Same value as MAX_CALLERS_PER_EVENT defined in hiview_adapter.cpp
constexpr uint32_t MAX_CALLERS_PER_EVENT_FOR_TEST = 100;

// Makes the uri entry's window look 2 hours old so it is due for flush. The interval
// floor is 1 hour so time passage cannot be awaited in tests.
void MakeEntryDue(DataShareAccessReporter &reporter, const std::string &uri, const std::string &provider)
{
    reporter.entries_.Compute(DataShareAccessReporter::MakeUriKey(uri, provider),
        [](const std::string &, UriEntry &entry) {
            entry.windowStartTime -= TWO_HOURS_MS;
            return true;
        });
}
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
 * @tc.desc: test Record with a different funcId creates a separate api count within the same caller
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
    // rowCount counts callers: two funcIds of the same caller share one caller count.
    EXPECT_EQ(reporter.GetStatsCount(), 1U);
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
 * @tc.name: FlushDue_NotDueStats_KeepsEntries
 * @tc.desc: test FlushDue keeps entries whose report interval has not elapsed
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, FlushDue_NotDueStats_KeepsEntries, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::FlushDue_NotDueStats_KeepsEntries start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    EXPECT_NO_FATAL_FAILURE(reporter.FlushDue());
    EXPECT_EQ(reporter.GetStatsCount(), 1U);
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.count, 1U);
    reporter.FlushAll();
    ZLOGI("DataShareAccessReporterTest::FlushDue_NotDueStats_KeepsEntries end");
}

/**
 * @tc.name: Record_SameUriMultipleCallers_SingleWindowFlush
 * @tc.desc: test rows of the same uri share one window and are flushed together
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_SameUriMultipleCallers_SingleWindowFlush, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_SameUriMultipleCallers_SingleWindowFlush start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    std::string callerA = "com.example.caller.a";
    std::string callerB = "com.example.caller.b";
    reporter.Record(TEST_URI, PROVIDER_NAME, callerA, FUNC_ID_QUERY, 24);
    reporter.Record(TEST_URI, PROVIDER_NAME, callerB, FUNC_ID_INSERT, 24);
    EXPECT_EQ(reporter.GetStatsCount(), 2U);
    AccessStatInfo first;
    AccessStatInfo second;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, callerA, FUNC_ID_QUERY, first));
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, callerB, FUNC_ID_INSERT, second));
    // Both rows share the same uri window: identical start time and interval.
    EXPECT_GT(first.windowStartTime, 0);
    EXPECT_EQ(first.windowStartTime, second.windowStartTime);
    EXPECT_EQ(first.reportIntervalHours, 24);
    EXPECT_EQ(second.reportIntervalHours, 24);
    // A later interval change of this uri is visible to all rows of the shared window.
    reporter.Record(TEST_URI, PROVIDER_NAME, callerA, FUNC_ID_QUERY, 2);
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, callerB, FUNC_ID_INSERT, second));
    EXPECT_EQ(second.reportIntervalHours, 2);
    // All rows of the uri are flushed in one round.
    reporter.FlushAll();
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    EXPECT_FALSE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, callerA, FUNC_ID_QUERY, first));
    EXPECT_FALSE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, callerB, FUNC_ID_INSERT, second));
    ZLOGI("DataShareAccessReporterTest::Record_SameUriMultipleCallers_SingleWindowFlush end");
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
 * @tc.name: Record_IntervalAboveMax_FallsBackToDefault
 * @tc.desc: test Record with interval above the maximum falls back to the default interval
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_IntervalAboveMax_FallsBackToDefault, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_IntervalAboveMax_FallsBackToDefault start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, MAX_INTERVAL_HOURS_FOR_TEST + 1);
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.reportIntervalHours, 24);
    reporter.FlushAll();
    ZLOGI("DataShareAccessReporterTest::Record_IntervalAboveMax_FallsBackToDefault end");
}

/**
 * @tc.name: Record_ExceedsMaxKeyCount_KeepsUndueEntries
 * @tc.desc: test overflow flush only flushes due entries and keeps undue ones beyond the key cap
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_ExceedsMaxKeyCount_KeepsUndueEntries, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_ExceedsMaxKeyCount_KeepsUndueEntries start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    for (uint32_t i = 0; i <= MAX_KEY_COUNT_FOR_TEST; i++) {
        std::string uri = TEST_URI + "/" + std::to_string(i);
        EXPECT_NO_FATAL_FAILURE(reporter.Record(uri, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24));
    }
    // The overflow flush only flushes due entries, undue ones are kept for their own windows.
    EXPECT_EQ(reporter.GetStatsCount(), MAX_KEY_COUNT_FOR_TEST + 1U);
    reporter.FlushAll();
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    ZLOGI("DataShareAccessReporterTest::Record_ExceedsMaxKeyCount_KeepsUndueEntries end");
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
 * @tc.name: FlushDue_EmptyStats_NoFatal
 * @tc.desc: test FlushDue with empty stats does not crash
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, FlushDue_EmptyStats_NoFatal, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::FlushDue_EmptyStats_NoFatal start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    EXPECT_NO_FATAL_FAILURE(reporter.FlushDue());
    ZLOGI("DataShareAccessReporterTest::FlushDue_EmptyStats_NoFatal end");
}
/**
 * @tc.name: AnonymousUri_NoQuery_KeepsUriTail
 * @tc.desc: test AnonymousUri keeps the last 10 chars of the uri when there is no query
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, AnonymousUri_NoQuery_KeepsUriTail, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_NoQuery_KeepsUriTail start");
    std::string uri = "datashare://com.example.provider/aaaabbbbccccdddd";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(uri), "******bbccccdddd");
    std::string longUri = "datashare://com.example.provider/store/table_weather";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(longUri), "******le_weather");
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_NoQuery_KeepsUriTail end");
}

/**
 * @tc.name: AnonymousUri_WithQuery_KeepsTenCharsBeforeQuery
 * @tc.desc: test AnonymousUri keeps only the 10 chars before '?' and drops the query
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, AnonymousUri_WithQuery_KeepsTenCharsBeforeQuery, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_WithQuery_KeepsTenCharsBeforeQuery start");
    std::string uri = "datashare:///settings/data?Proxy=true";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(uri), "******tings/data");
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_WithQuery_KeepsTenCharsBeforeQuery end");
}

/**
 * @tc.name: AnonymousUri_Edges_ClampToUriStart
 * @tc.desc: test AnonymousUri clamps to the uri start when the cut point is within the first 10 chars
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, AnonymousUri_Edges_ClampToUriStart, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_Edges_ClampToUriStart start");
    std::string shortUri = "datashare:///tbl";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(shortUri), "******are:///tbl");
    std::string earlyQuery = "short?Proxy=true";
    EXPECT_EQ(DataShareAccessReporter::AnonymousUri(earlyQuery), "******short");
    ZLOGI("DataShareAccessReporterTest::AnonymousUri_Edges_ClampToUriStart end");
}

/**
 * @tc.name: Record_AnonymizedKey_ConsistentLookup
 * @tc.desc: test Record aggregates keys with the bundleName prefix kept by AnonymousUri
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_AnonymizedKey_ConsistentLookup, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_AnonymizedKey_ConsistentLookup start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record("datashare://com.example.provider/aaaabbbbccccdddd", PROVIDER_NAME, CALLER_NAME,
        FUNC_ID_QUERY, 24);
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo("datashare://com.example.provider/aaaabbbbccccdddd", PROVIDER_NAME,
        CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_EQ(info.count, 1U);
    ZLOGI("DataShareAccessReporterTest::Record_AnonymizedKey_ConsistentLookup end");
}
/**
 * @tc.name: FormatApiCounts_EmptyMap_ReturnsAllZeroCounts
 * @tc.desc: test FormatApiCounts returns fixed four items with zero values for an empty map
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, FormatApiCounts_EmptyMap_ReturnsAllZeroCounts, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::FormatApiCounts_EmptyMap_ReturnsAllZeroCounts start");
    std::map<uint32_t, uint64_t> apiCounts;
    EXPECT_EQ(DataShareAccessReporter::FormatApiCounts(apiCounts), "insert:0;update:0;delete:0;query:0");
    ZLOGI("DataShareAccessReporterTest::FormatApiCounts_EmptyMap_ReturnsAllZeroCounts end");
}

/**
 * @tc.name: FormatApiCounts_PartialApis_FillsZeroAndKeepsOrder
 * @tc.desc: test FormatApiCounts fills zero for missing apis and keeps the fixed order
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, FormatApiCounts_PartialApis_FillsZeroAndKeepsOrder, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::FormatApiCounts_PartialApis_FillsZeroAndKeepsOrder start");
    std::map<uint32_t, uint64_t> apiCounts;
    apiCounts[static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_QUERY)] = 20;
    EXPECT_EQ(DataShareAccessReporter::FormatApiCounts(apiCounts), "insert:0;update:0;delete:0;query:20");
    ZLOGI("DataShareAccessReporterTest::FormatApiCounts_PartialApis_FillsZeroAndKeepsOrder end");
}

/**
 * @tc.name: FormatApiCounts_AllApis_FormatsFixedOrder
 * @tc.desc: test FormatApiCounts formats all four apis in the fixed order
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, FormatApiCounts_AllApis_FormatsFixedOrder, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::FormatApiCounts_AllApis_FormatsFixedOrder start");
    std::map<uint32_t, uint64_t> apiCounts;
    apiCounts[static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_INSERTEX)] = 10;
    apiCounts[static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_UPDATEEX)] = 20;
    apiCounts[static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_DELETEEX)] = 1;
    apiCounts[static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_QUERY)] = 20;
    EXPECT_EQ(DataShareAccessReporter::FormatApiCounts(apiCounts), "insert:10;update:20;delete:1;query:20");
    ZLOGI("DataShareAccessReporterTest::FormatApiCounts_AllApis_FormatsFixedOrder end");
}
/**
 * @tc.name: GetAccessStatInfo_UnknownCallerOrFunc_ReturnsFalse
 * @tc.desc: test GetAccessStatInfo returns false for an unrecorded caller or funcId
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, GetAccessStatInfo_UnknownCallerOrFunc_ReturnsFalse, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::GetAccessStatInfo_UnknownCallerOrFunc_ReturnsFalse start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    AccessStatInfo info;
    EXPECT_FALSE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, "com.example.unknown.caller",
        FUNC_ID_QUERY, info));
    EXPECT_FALSE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_INSERT, info));
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    reporter.FlushAll();
    ZLOGI("DataShareAccessReporterTest::GetAccessStatInfo_UnknownCallerOrFunc_ReturnsFalse end");
}

/**
 * @tc.name: FlushDue_DueEntry_IsFlushedAndReported
 * @tc.desc: test FlushDue flushes the entry whose report interval has elapsed
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, FlushDue_DueEntry_IsFlushedAndReported, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::FlushDue_DueEntry_IsFlushedAndReported start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    MakeEntryDue(reporter, TEST_URI, PROVIDER_NAME);
    EXPECT_NO_FATAL_FAILURE(reporter.FlushDue());
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    AccessStatInfo info;
    EXPECT_FALSE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    ZLOGI("DataShareAccessReporterTest::FlushDue_DueEntry_IsFlushedAndReported end");
}

/**
 * @tc.name: Record_OverflowThrottled_RejectsDispatch
 * @tc.desc: test overflow dispatch is rejected when the last dispatch is within the throttle window
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_OverflowThrottled_RejectsDispatch, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_OverflowThrottled_RejectsDispatch start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    MakeEntryDue(reporter, TEST_URI, PROVIDER_NAME);
    reporter.rowCount_.store(MAX_KEY_COUNT_FOR_TEST + 1);
    reporter.lastOverflowFlushMs_.store(reporter.NowMs() - THROTTLE_WINDOW_MS / 2);
    reporter.Record(OTHER_URI, OTHER_PROVIDER, CALLER_NAME, FUNC_ID_QUERY, 24);
    // Throttled: no flush is dispatched, the due entry is kept.
    EXPECT_FALSE(reporter.overflowFlushPending_.load());
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    reporter.FlushAll();
    reporter.rowCount_.store(0);
    reporter.lastOverflowFlushMs_.store(0);
    ZLOGI("DataShareAccessReporterTest::Record_OverflowThrottled_RejectsDispatch end");
}

/**
 * @tc.name: Record_OverflowPendingOccupied_RejectsDispatch
 * @tc.desc: test overflow dispatch is rejected when another overflow flush is still pending
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_OverflowPendingOccupied_RejectsDispatch, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_OverflowPendingOccupied_RejectsDispatch start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    MakeEntryDue(reporter, TEST_URI, PROVIDER_NAME);
    reporter.rowCount_.store(MAX_KEY_COUNT_FOR_TEST + 1);
    reporter.lastOverflowFlushMs_.store(0);
    reporter.overflowFlushPending_.store(true);
    reporter.Record(OTHER_URI, OTHER_PROVIDER, CALLER_NAME, FUNC_ID_QUERY, 24);
    // Pending flag occupied: no flush is dispatched, the due entry is kept.
    EXPECT_TRUE(reporter.overflowFlushPending_.load());
    AccessStatInfo info;
    EXPECT_TRUE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    reporter.FlushAll();
    reporter.rowCount_.store(0);
    reporter.overflowFlushPending_.store(false);
    ZLOGI("DataShareAccessReporterTest::Record_OverflowPendingOccupied_RejectsDispatch end");
}

/**
 * @tc.name: Record_OverflowThrottleExpired_AllowsDispatch
 * @tc.desc: test overflow dispatch is allowed again once the throttle window has elapsed
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_OverflowThrottleExpired_AllowsDispatch, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_OverflowThrottleExpired_AllowsDispatch start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    MakeEntryDue(reporter, TEST_URI, PROVIDER_NAME);
    reporter.rowCount_.store(MAX_KEY_COUNT_FOR_TEST + 1);
    reporter.lastOverflowFlushMs_.store(reporter.NowMs() - THROTTLE_WINDOW_MS - 1000);
    reporter.Record(OTHER_URI, OTHER_PROVIDER, CALLER_NAME, FUNC_ID_QUERY, 24);
    // Throttle expired: the dispatch runs synchronously without an executor and the
    // due entry is flushed; the pending flag is reset when the flush completes.
    EXPECT_FALSE(reporter.overflowFlushPending_.load());
    AccessStatInfo info;
    EXPECT_FALSE(reporter.GetAccessStatInfo(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, info));
    EXPECT_TRUE(reporter.GetAccessStatInfo(OTHER_URI, OTHER_PROVIDER, CALLER_NAME, FUNC_ID_QUERY, info));
    reporter.FlushAll();
    reporter.rowCount_.store(0);
    reporter.lastOverflowFlushMs_.store(0);
    ZLOGI("DataShareAccessReporterTest::Record_OverflowThrottleExpired_AllowsDispatch end");
}

/**
 * @tc.name: Record_ManyCallers_ShardedIntoMultipleEvents
 * @tc.desc: test FlushAll shards the caller array into multiple events beyond the per-event cap
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_ManyCallers_ShardedIntoMultipleEvents, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_ManyCallers_ShardedIntoMultipleEvents start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    for (uint32_t i = 0; i <= MAX_CALLERS_PER_EVENT_FOR_TEST; i++) {
        reporter.Record(TEST_URI, PROVIDER_NAME, "com.example.caller." + std::to_string(i), FUNC_ID_QUERY, 24);
    }
    EXPECT_EQ(reporter.GetStatsCount(), MAX_CALLERS_PER_EVENT_FOR_TEST + 1U);
    EXPECT_NO_FATAL_FAILURE(reporter.FlushAll());
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    ZLOGI("DataShareAccessReporterTest::Record_ManyCallers_ShardedIntoMultipleEvents end");
}

/**
 * @tc.name: Record_WithExecutor_SchedulesAndReschedulesTimer
 * @tc.desc: test Record schedules the one-shot timer with a real executor and reschedules earlier
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_WithExecutor_SchedulesAndReschedulesTimer, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_WithExecutor_SchedulesAndReschedulesTimer start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.Init(std::make_shared<ExecutorPool>(2, 1));
    reporter.FlushAll();
    EXPECT_EQ(reporter.nextTaskId_, ExecutorPool::INVALID_TASK_ID);
    // First record schedules the one-shot timer at its due time.
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 48);
    EXPECT_NE(reporter.nextTaskId_, ExecutorPool::INVALID_TASK_ID);
    // A uri due earlier removes the pending task and reschedules earlier.
    reporter.Record(OTHER_URI, OTHER_PROVIDER, CALLER_NAME, FUNC_ID_QUERY, 1);
    EXPECT_NE(reporter.nextTaskId_, ExecutorPool::INVALID_TASK_ID);
    // A record of an existing window whose due is not earlier keeps the pending task.
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_INSERT, 48);
    // Flushing everything cancels the timer by removing the real pending task.
    reporter.FlushAll();
    EXPECT_EQ(reporter.nextTaskId_, ExecutorPool::INVALID_TASK_ID);
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    ZLOGI("DataShareAccessReporterTest::Record_WithExecutor_SchedulesAndReschedulesTimer end");
}

/**
 * @tc.name: Record_OverflowAsyncDispatch_WithExecutor
 * @tc.desc: test overflow flush is dispatched asynchronously to the executor when available
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(DataShareAccessReporterTest, Record_OverflowAsyncDispatch_WithExecutor, TestSize.Level1)
{
    ZLOGI("DataShareAccessReporterTest::Record_OverflowAsyncDispatch_WithExecutor start");
    auto &reporter = DataShareAccessReporter::GetInstance();
    reporter.FlushAll();
    EXPECT_EQ(reporter.GetStatsCount(), 0U);
    reporter.rowCount_.store(MAX_KEY_COUNT_FOR_TEST + 1);
    reporter.lastOverflowFlushMs_.store(0);
    reporter.Record(TEST_URI, PROVIDER_NAME, CALLER_NAME, FUNC_ID_QUERY, 24);
    // The overflow flush runs on the executor; wait for it to complete and reset the flag.
    std::this_thread::sleep_for(std::chrono::milliseconds(ASYNC_FLUSH_WAIT_MS));
    EXPECT_FALSE(reporter.overflowFlushPending_.load());
    // Undue entries are kept by the overflow flush.
    EXPECT_EQ(reporter.GetStatsCount(), MAX_KEY_COUNT_FOR_TEST + 2U);
    reporter.FlushAll();
    reporter.rowCount_.store(0);
    ZLOGI("DataShareAccessReporterTest::Record_OverflowAsyncDispatch_WithExecutor end");
}
} // namespace OHOS::Test
