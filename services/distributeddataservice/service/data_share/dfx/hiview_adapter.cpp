/*
* Copyright (c) 2025 Huawei Device Co., Ltd.
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
#define LOG_TAG "HiViewAdapter"

#include "hiview_adapter.h"

#include <algorithm>
#include <limits>

#include "hiview_fault_adapter.h"
#include "log_print.h"
#include "utils.h"

namespace OHOS {
namespace DataShare {
namespace {
constexpr char DOMAIN[] = "DISTDATAMGR";
constexpr const char *EVENT_NAME = "DATA_SHARE_STATISTIC";
constexpr const uint32_t MAX_COLLECT_COUNT = 20;
constexpr const uint32_t MIN_CALL_COUNT = 1000;
constexpr const size_t PARAMS_SIZE = 7;
constexpr const char *ACCESS_EVENT_NAME = "DATA_SHARE_ACCESS_STATISTIC";
constexpr const uint32_t MAX_KEY_COUNT = 5000;
constexpr const uint32_t MAX_CALLERS_PER_EVENT = 100;
constexpr const size_t ACCESS_PARAMS_SIZE = 4;
constexpr const int32_t MIN_REPORT_INTERVAL_HOURS = 1;
constexpr const int32_t MAX_REPORT_INTERVAL_HOURS = 48;
constexpr const int32_t DEFAULT_REPORT_INTERVAL_HOURS = 24;
// Minimum interval between two overflow flush dispatches, prevents tight dispatch
// loops when the key count stays above the cap with only undue entries.
constexpr const int64_t OVERFLOW_FLUSH_THROTTLE_MS = 60LL * 1000;
constexpr const int64_t MILLISECONDS_PER_HOUR = 3600LL * 1000;
constexpr const int32_t URI_KEEP_LENGTH = 10;
constexpr const char *URI_ANONYMOUS_MARK = "******";
}

using namespace std::chrono;

HiViewAdapter& HiViewAdapter::GetInstance()
{
    static HiViewAdapter instance;
    return instance;
}

void HiViewAdapter::ReportDataStatistic(const CallerInfo &callerInfo)
{
    if (executors_ == nullptr) {
        ZLOGE("executors is nullptr, collect failed");
        return;
    }

    callers_.Compute(callerInfo.callerTokenId, [&callerInfo, this](const uint64_t &key, CallerTotalInfo &value) {
        if (value.totalCount == 0) {
            value.callerUid = callerInfo.callerUid;
            std::string callingName = HiViewFaultAdapter::GetCallingName(key).first;
            value.callerName = callingName.empty() ? std::to_string(callerInfo.callerPid) : callingName;
        }
        value.totalCount += 1;
        value.maxCostTime = std::max(callerInfo.costTime, value.maxCostTime);
        value.totalCostTime += callerInfo.costTime;
        value.slowRequestCount = value.slowRequestCount + (callerInfo.isSlowRequest ? 1 : 0);
        auto it = funcIdMap_.find(callerInfo.funcId);
        if (it != funcIdMap_.end()) {
            auto funcName = it->second;
            value.funcCounts[funcName] = value.funcCounts[funcName] + 1;
        }
        return true;
    });
}

void HiViewAdapter::InvokeData()
{
    uint32_t mapSize = callers_.Size();
    if (mapSize == 0) { return; }
    std::vector<CallerTotalInfo> callerTotalInfos;
    GetCallerTotalInfoVec(callerTotalInfos);
    uint32_t count = std::min(static_cast<uint32_t>(callerTotalInfos.size()), MAX_COLLECT_COUNT);
    if (count == 0) { return; }
    std::vector<int64_t> callerUids(count);
    std::vector<char*> callerNames(count);
    std::vector<int64_t> totalCounts(count);
    std::vector<int64_t> slowRequestCounts(count);
    std::vector<int64_t> maxCostTimes(count);
    std::vector<int64_t> totalCostTimes(count);
    std::vector<char*> funcCounts(count);
    std::vector<std::string> funcCountsHolder(count);
    for (uint32_t i = 0; i < count; i++) {
        CallerTotalInfo &callerTotalInfo = callerTotalInfos[i];
        callerUids[i] = callerTotalInfo.callerUid;
        callerNames[i] = const_cast<char *>(callerTotalInfo.callerName.c_str());
        totalCounts[i] = callerTotalInfo.totalCount;
        slowRequestCounts[i] = callerTotalInfo.slowRequestCount;
        maxCostTimes[i] = callerTotalInfo.maxCostTime;
        totalCostTimes[i] = callerTotalInfo.totalCostTime;
        std::string funcCount = "{";
        for (const auto &it : callerTotalInfo.funcCounts) {
            funcCount += it.first + ":" + std::to_string(it.second) + ",";
        }
        funcCount = funcCount.substr(0, funcCount.size() - 1) + "}";
        funcCountsHolder[i] = std::move(funcCount);
        funcCounts[i] = const_cast<char *>(funcCountsHolder[i].c_str());
    }

    HiSysEventParam callerUid = { .name = "COLLIE_UID", .t = HISYSEVENT_INT64_ARRAY,
        .v = { .array = callerUids.data() }, .arraySize = count };
    HiSysEventParam callerName = { .name = "CALLER_NAME", .t = HISYSEVENT_STRING_ARRAY,
        .v = { .array = callerNames.data() }, .arraySize = count };
    HiSysEventParam totalCount = { .name = "TOTAL_COUNT", .t = HISYSEVENT_INT64_ARRAY,
        .v = { .array = totalCounts.data() }, .arraySize = count };
    HiSysEventParam slowRequestCount = { .name = "SLOW_RQUEST_COUNT", .t = HISYSEVENT_INT64_ARRAY,
        .v = { .array = slowRequestCounts.data() }, .arraySize = count };
    HiSysEventParam maxCostTime = { .name = "MAX_COST_TIME", .t = HISYSEVENT_INT64_ARRAY,
        .v = { .array = maxCostTimes.data() }, .arraySize = count };
    HiSysEventParam totalCostTime = { .name = "TOTAL_COST_TIME", .t = HISYSEVENT_INT64_ARRAY,
        .v = { .array = totalCostTimes.data() }, .arraySize = count };
    HiSysEventParam funcCount = { .name = "FUNC_COUNTS", .t = HISYSEVENT_STRING_ARRAY,
        .v = { .array = funcCounts.data() }, .arraySize = count };
    HiSysEventParam params[] = {callerUid, callerName, totalCount, slowRequestCount,
        maxCostTime, totalCostTime, funcCount};
    int res = OH_HiSysEvent_Write(DOMAIN, EVENT_NAME, HISYSEVENT_STATISTIC, params, PARAMS_SIZE);
    ZLOGI("OH_HiSysEvent_Write, res = %{public}d", res);
}

void HiViewAdapter::GetCallerTotalInfoVec(std::vector<CallerTotalInfo> &callerTotalInfos)
{
    callers_.EraseIf([&callerTotalInfos](const uint64_t key, CallerTotalInfo &callerTotalInfo) {
        if (callerTotalInfo.totalCount >= MIN_CALL_COUNT)
            callerTotalInfos.push_back(callerTotalInfo);
        return true;
    });
    std::sort(callerTotalInfos.begin(), callerTotalInfos.end(),
        [](const CallerTotalInfo &first, const CallerTotalInfo &second) {
        return first.totalCount > second.totalCount;
    });
}

DataShareAccessReporter &DataShareAccessReporter::GetInstance()
{
    static DataShareAccessReporter instance;
    return instance;
}

std::string DataShareAccessReporter::AnonymousUri(const std::string &uri)
{
    // The event carries the provider bundleName as a dedicated field, so the uri only
    // keeps the last URI_KEEP_LENGTH chars before the query: no query means the uri
    // tail, a query means from 10 chars before '?' to the end (query included).
    size_t cut = uri.find('?');
    if (cut == std::string::npos) {
        cut = uri.length();
    }
    cut = (cut >= URI_KEEP_LENGTH) ? cut - URI_KEEP_LENGTH : 0;
    return URI_ANONYMOUS_MARK + uri.substr(cut);
}

std::string DataShareAccessReporter::FormatApiCounts(const std::map<uint32_t, uint64_t> &apiCounts)
{
    // Fixed api order with zero values included, e.g. "insert:0;update:2;delete:0;query:5".
    static const std::pair<uint32_t, const char *> API_ORDER[] = {
        { static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_INSERTEX), "insert" },
        { static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_UPDATEEX), "update" },
        { static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_DELETEEX), "delete" },
        { static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_QUERY), "query" },
    };
    std::string result;
    for (size_t i = 0; i < sizeof(API_ORDER) / sizeof(API_ORDER[0]); i++) {
        if (i > 0) {
            result += ";";
        }
        auto it = apiCounts.find(API_ORDER[i].first);
        result += std::string(API_ORDER[i].second) + ":" +
            std::to_string(it != apiCounts.end() ? it->second : 0);
    }
    return result;
}

std::string DataShareAccessReporter::MakeUriKey(const std::string &uri, const std::string &providerBundleName)
{
    // The provider stays in the key (not in the displayed uri) so that uris of
    // different providers sharing the same anonymized tail never merge into one window.
    return AnonymousUri(uri) + "|" + providerBundleName;
}

void DataShareAccessReporter::Record(const std::string &uri, const std::string &providerBundleName,
    const std::string &callerBundleName, uint32_t funcId, int32_t reportIntervalHours)
{
    int64_t now = NowMs();
    std::string uriKey = MakeUriKey(uri, providerBundleName);
    int64_t windowStart = 0;
    int32_t interval = DEFAULT_REPORT_INTERVAL_HOURS;
    {
        // The whole record is serialized with flushes so a row can never land in an
        // entry that is being flushed.
        std::lock_guard<std::mutex> lock(flushMutex_);
        entries_.Compute(uriKey, [&uri, &providerBundleName, &callerBundleName, &funcId, &reportIntervalHours,
            &now, &windowStart, &interval, this](const std::string &, UriEntry &entry) {
            if (entry.windowStartTime == 0) {
                entry.windowStartTime = now;
                entry.uri = uri;
                entry.providerBundleName = providerBundleName;
            }
            // The interval is configured at uri granularity: the latest configuration
            // of this uri wins (clamped to [MIN, MAX]), other uris are never affected.
            if (reportIntervalHours >= MIN_REPORT_INTERVAL_HOURS) {
                entry.reportIntervalHours = std::min(reportIntervalHours, MAX_REPORT_INTERVAL_HOURS);
            }
            // rowCount_ bounds the caller count across all entries (memory cap metric).
            std::map<uint32_t, uint64_t> &apiCounts = entry.callers[callerBundleName];
            if (apiCounts.empty()) {
                rowCount_.fetch_add(1);
            }
            apiCounts[funcId] += 1;
            windowStart = entry.windowStartTime;
            interval = entry.reportIntervalHours;
            return true;
        });
        if (executors_ != nullptr) {
            int64_t due = windowStart + static_cast<int64_t>(interval) * MILLISECONDS_PER_HOUR;
            if (nextTaskId_ == ExecutorPool::INVALID_TASK_ID || due < nextFireTimeMs_) {
                ScheduleLocked(due);
            }
        }
    }
    if (rowCount_.load() > MAX_KEY_COUNT && TryDispatchOverflowFlush()) {
        ZLOGW("access stats overflow, rowCount:%{public}zu, entries:%{public}zu, uri:%{public}s",
            rowCount_.load(), entries_.Size(), uriKey.c_str());
        if (executors_ != nullptr) {
            // Flush asynchronously to avoid blocking the calling binder thread.
            // Only due entries are flushed: a forced full flush would report undue
            // entries early and reset their aggregation windows.
            executors_->Execute([this]() { FlushDue(); });
        } else {
            FlushDue();
        }
    }
}

void DataShareAccessReporter::Init(std::shared_ptr<ExecutorPool> executors)
{
    executors_ = std::move(executors);
}

void DataShareAccessReporter::FlushAll()
{
    FlushEntries(true);
}

void DataShareAccessReporter::FlushDue()
{
    FlushEntries(false);
}

size_t DataShareAccessReporter::GetStatsCount()
{
    return rowCount_.load();
}

bool DataShareAccessReporter::GetAccessStatInfo(const std::string &uri, const std::string &providerBundleName,
    const std::string &callerBundleName, uint32_t funcId, AccessStatInfo &info)
{
    std::string uriKey = MakeUriKey(uri, providerBundleName);
    bool found = false;
    entries_.ComputeIfPresent(uriKey,
        [&callerBundleName, &funcId, &info, &found](const std::string &, UriEntry &entry) {
            auto callerIt = entry.callers.find(callerBundleName);
            if (callerIt == entry.callers.end()) {
                return true;
            }
            auto apiIt = callerIt->second.find(funcId);
            if (apiIt == callerIt->second.end()) {
                return true;
            }
            info.uri = entry.uri;
            info.providerBundleName = entry.providerBundleName;
            info.callerBundleName = callerIt->first;
            info.funcId = apiIt->first;
            info.count = apiIt->second;
            // Backfill the owning entry's window state so callers can inspect the shared window.
            info.windowStartTime = entry.windowStartTime;
            info.reportIntervalHours = entry.reportIntervalHours;
            found = true;
            return true;
        });
    return found;
}

bool DataShareAccessReporter::TryDispatchOverflowFlush()
{
    // Deduplicate overflow flush dispatches: without the pending flag every Record
    // above the key cap would enqueue a new flush task and flood the executor pool.
    int64_t now = NowMs();
    int64_t last = lastOverflowFlushMs_.load();
    if (last != 0 && now - last < OVERFLOW_FLUSH_THROTTLE_MS) {
        return false;
    }
    if (overflowFlushPending_.exchange(true)) {
        return false;
    }
    lastOverflowFlushMs_.store(now);
    return true;
}

void DataShareAccessReporter::FlushEntries(bool forceAll)
{
    std::vector<UriEntry> dueEntries;
    {
        // Serialize flushes: concurrent timer/overflow flushes must not split one
        // reporting round into several partial events.
        std::lock_guard<std::mutex> lock(flushMutex_);
        int64_t now = NowMs();
        // Flush due entries: each due uri is reported as one complete snapshot of
        // its configured interval.
        entries_.EraseIf([&dueEntries, forceAll, now, this](const std::string &, UriEntry &entry) {
            if (forceAll || DueTimeMsLocked(entry) <= now) {
                rowCount_.fetch_sub(entry.callers.size());
                dueEntries.push_back(std::move(entry));
                return true;
            }
            return false;
        });
        // Reschedule on the earliest due time among the remaining entries.
        int64_t nextFire = std::numeric_limits<int64_t>::max();
        entries_.ForEach([&nextFire, this](const std::string &, UriEntry &entry) {
            nextFire = std::min(nextFire, DueTimeMsLocked(entry));
            return false;
        });
        if (nextFire == std::numeric_limits<int64_t>::max()) {
            // No entries left: cancel the pending timer explicitly so a stale task
            // cannot fire later on empty stats.
            CancelTimerLocked();
        } else {
            // Defensive guard: an already-expired next fire time must never produce
            // a zero-delay reschedule loop.
            if (nextFire <= now) {
                nextFire = now + MILLISECONDS_PER_HOUR;
            }
            ScheduleLocked(nextFire);
        }
    }
    for (const auto &entry : dueEntries) {
        ReportEntry(entry);
    }
    overflowFlushPending_.store(false);
}

void DataShareAccessReporter::ScheduleLocked(int64_t fireAtMs)
{
    if (executors_ == nullptr) {
        return;
    }
    if (nextTaskId_ != ExecutorPool::INVALID_TASK_ID) {
        executors_->Remove(nextTaskId_);
    }
    int64_t delayMs = std::max(fireAtMs - NowMs(), static_cast<int64_t>(0));
    nextFireTimeMs_ = fireAtMs;
    // One-shot form (delay first); the next round is scheduled in FlushEntries,
    // so no repeated task leaks and the fire time always follows entry due times.
    nextTaskId_ = executors_->Schedule(std::chrono::milliseconds(delayMs), [this]() { FlushDue(); });
}

void DataShareAccessReporter::CancelTimerLocked()
{
    if (nextTaskId_ != ExecutorPool::INVALID_TASK_ID) {
        if (executors_ != nullptr) {
            executors_->Remove(nextTaskId_);
        }
        nextTaskId_ = ExecutorPool::INVALID_TASK_ID;
    }
    nextFireTimeMs_ = 0;
}

int64_t DataShareAccessReporter::DueTimeMsLocked(const UriEntry &entry) const
{
    return entry.windowStartTime + static_cast<int64_t>(entry.reportIntervalHours) * MILLISECONDS_PER_HOUR;
}

int64_t DataShareAccessReporter::NowMs() const
{
    // Monotonic clock: window durations and scheduling must not be affected by
    // wall-clock adjustments (NTP sync or manual time changes).
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

void DataShareAccessReporter::ReportEntry(const UriEntry &entry)
{
    // One event per uri: URI and provider are scalars, the caller array and the
    // per-caller api count array are parallel. Very large caller arrays are sharded
    // into several events to bound the single write size.
    std::string anonymizedUri = AnonymousUri(entry.uri);
    std::vector<std::string> callerHolder;
    std::vector<std::string> apiCountHolder;
    auto writeEvent = [this, &anonymizedUri, &entry, &callerHolder, &apiCountHolder]() {
        uint32_t count = static_cast<uint32_t>(callerHolder.size());
        std::vector<char *> callers(count);
        std::vector<char *> apiCounts(count);
        for (uint32_t i = 0; i < count; i++) {
            callers[i] = const_cast<char *>(callerHolder[i].c_str());
            apiCounts[i] = const_cast<char *>(apiCountHolder[i].c_str());
        }
        HiSysEventParam uri = {
            .name = "URI", .t = HISYSEVENT_STRING, .v = { .s = const_cast<char *>(anonymizedUri.c_str()) },
            .arraySize = 0
        };
        HiSysEventParam provider = { .name = "PROVIDER_BUNDLE_NAME", .t = HISYSEVENT_STRING,
            .v = { .s = const_cast<char *>(entry.providerBundleName.c_str()) }, .arraySize = 0 };
        HiSysEventParam caller = { .name = "CALLER_BUNDLE_NAME", .t = HISYSEVENT_STRING_ARRAY,
            .v = { .array = callers.data() }, .arraySize = count };
        HiSysEventParam apiCallCount = { .name = "API_CALL_COUNT", .t = HISYSEVENT_STRING_ARRAY,
            .v = { .array = apiCounts.data() }, .arraySize = count };
        HiSysEventParam params[] = { uri, provider, caller, apiCallCount };
        int res = OH_HiSysEvent_Write(DOMAIN, ACCESS_EVENT_NAME, HISYSEVENT_STATISTIC, params, ACCESS_PARAMS_SIZE);
        ZLOGI("OH_HiSysEvent_Write access statistic, res = %{public}d, callers = %{public}u", res, count);
        callerHolder.clear();
        apiCountHolder.clear();
    };
    for (const auto &caller : entry.callers) {
        callerHolder.push_back(caller.first);
        apiCountHolder.push_back(FormatApiCounts(caller.second));
        if (callerHolder.size() >= MAX_CALLERS_PER_EVENT) {
            writeEvent();
        }
    }
    if (!callerHolder.empty()) {
        writeEvent();
    }
}
} // namespace DataShare
} // namespace OHOS