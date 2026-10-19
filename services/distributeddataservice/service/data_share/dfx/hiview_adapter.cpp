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

#include "common_utils.h"
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
constexpr const uint32_t MAX_REPORT_BATCH = 50;
constexpr const uint32_t MAX_KEY_COUNT = 5000;
constexpr const int32_t MIN_REPORT_INTERVAL_HOURS = 1;
constexpr const int32_t MAX_REPORT_INTERVAL_HOURS = 48;
constexpr const int32_t DEFAULT_REPORT_INTERVAL_HOURS = 24;
constexpr const int64_t MILLISECONDS_PER_HOUR = 3600LL * 1000;
constexpr const size_t ACCESS_PARAMS_SIZE = 5;
constexpr const int32_t URI_KEEP_LENGTH = 10;
constexpr const char *URI_ANONYMOUS_MARK = "******";

std::string GetInterfaceName(uint32_t funcId)
{
    switch (funcId) {
        case static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_QUERY):
            return "OnQuery";
        case static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_INSERTEX):
            return "OnInsertEx";
        case static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_DELETEEX):
            return "OnDeleteEx";
        case static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_UPDATEEX):
            return "OnUpdateEx";
        default:
            return std::to_string(funcId);
    }
}
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
    // Keep only the bundleName and the last URI_KEEP_LENGTH chars of the rest,
    // so the reported uri keeps the provider identity while user-related fields stay anonymized.
    size_t schemePos = uri.find("://");
    if (schemePos == std::string::npos) {
        return URIUtils::Anonymous(uri);
    }
    size_t authorityStart = schemePos + strlen("://");
    size_t authorityEnd = uri.find('/', authorityStart);
    if (authorityEnd == std::string::npos) {
        return uri.substr(authorityStart);
    }
    std::string authority = uri.substr(authorityStart, authorityEnd - authorityStart);
    std::string suffix = uri.substr(authorityEnd);
    if (suffix.length() <= URI_KEEP_LENGTH) {
        return authority + suffix;
    }
    return authority + URI_ANONYMOUS_MARK +
        suffix.substr(suffix.length() - URI_KEEP_LENGTH, URI_KEEP_LENGTH);
}

std::string DataShareAccessReporter::MakeKey(const std::string &uri, const std::string &providerBundleName,
    const std::string &callerBundleName, uint32_t funcId)
{
    return AnonymousUri(uri) + "|" + providerBundleName + "|" + callerBundleName + "|" + std::to_string(funcId);
}

void DataShareAccessReporter::Record(const std::string &uri, const std::string &providerBundleName,
    const std::string &callerBundleName, uint32_t funcId, int32_t reportIntervalHours)
{
    int64_t now = GetSystemTime();
    std::string key = MakeKey(uri, providerBundleName, callerBundleName, funcId);
    int64_t windowStart = 0;
    int32_t interval = DEFAULT_REPORT_INTERVAL_HOURS;
    stats_.Compute(key, [&uri, &providerBundleName, &callerBundleName, &funcId, &reportIntervalHours, &now,
        &windowStart, &interval](const std::string &, AccessStatInfo &value) {
        if (value.count == 0) {
            value.uri = uri;
            value.providerBundleName = providerBundleName;
            value.callerBundleName = callerBundleName;
            value.funcId = funcId;
            value.windowStartTime = now;
        }
        // Each provider's configured interval is kept by its own entry, later callers
        // never override other providers' intervals.
        if (reportIntervalHours >= MIN_REPORT_INTERVAL_HOURS) {
            value.reportIntervalHours = reportIntervalHours;
        }
        value.count += 1;
        windowStart = value.windowStartTime;
        interval = value.reportIntervalHours;
        return true;
    });
    {
        std::lock_guard<std::mutex> lock(flushMutex_);
        if (executors_ != nullptr) {
            int64_t due = windowStart + static_cast<int64_t>(std::min(interval * overflowFactor_,
                MAX_REPORT_INTERVAL_HOURS)) * MILLISECONDS_PER_HOUR;
            if (nextTaskId_ == ExecutorPool::INVALID_TASK_ID || due < nextFireTimeMs_) {
                ScheduleLocked(due);
            }
        }
    }
    if (stats_.Size() > MAX_KEY_COUNT) {
        if (executors_ != nullptr) {
            // Flush asynchronously to avoid blocking the calling binder thread.
            executors_->Execute([this]() { FlushDueEntries(true); });
        } else {
            FlushDueEntries(true);
        }
    }
}

void DataShareAccessReporter::Init(std::shared_ptr<ExecutorPool> executors)
{
    executors_ = executors;
}

void DataShareAccessReporter::FlushAll()
{
    FlushDueEntries(true);
}

size_t DataShareAccessReporter::GetStatsCount()
{
    return stats_.Size();
}

bool DataShareAccessReporter::GetAccessStatInfo(const std::string &uri, const std::string &providerBundleName,
    const std::string &callerBundleName, uint32_t funcId, AccessStatInfo &info)
{
    std::string key = MakeKey(uri, providerBundleName, callerBundleName, funcId);
    bool found = false;
    stats_.ComputeIfPresent(key, [&info, &found](const std::string &, AccessStatInfo &value) {
        info = value;
        found = true;
        return true;
    });
    return found;
}

void DataShareAccessReporter::InvokeData()
{
    FlushDueEntries(false);
}

void DataShareAccessReporter::FlushDueEntries(bool forceAll)
{
    std::vector<AccessStatInfo> due;
    {
        // Serialize flushes: concurrent timer/overflow flushes must not split one
        // reporting round into several partial ReportBatch calls.
        std::lock_guard<std::mutex> lock(flushMutex_);
        int64_t now = GetSystemTime();
        stats_.EraseIf([&due, forceAll, now, this](const std::string &, AccessStatInfo &value) {
            if (forceAll || DueTimeMsLocked(value) <= now) {
                due.push_back(value);
                return true;
            }
            return false;
        });
        overflowFactor_ = (due.size() > MAX_KEY_COUNT)
            ? std::min(overflowFactor_ * 2, MAX_REPORT_INTERVAL_HOURS) : 1;
        int64_t nextFire = std::numeric_limits<int64_t>::max();
        stats_.ForEach([&nextFire, this](const std::string &, AccessStatInfo &value) {
            nextFire = std::min(nextFire, DueTimeMsLocked(value));
            return false;
        });
        if (nextFire == std::numeric_limits<int64_t>::max()) {
            nextTaskId_ = ExecutorPool::INVALID_TASK_ID;
            nextFireTimeMs_ = 0;
        } else {
            ScheduleLocked(nextFire);
        }
    }
    ReportInBatches(due);
}

void DataShareAccessReporter::ScheduleLocked(int64_t fireAtMs)
{
    if (executors_ == nullptr) {
        return;
    }
    if (nextTaskId_ != ExecutorPool::INVALID_TASK_ID) {
        executors_->Remove(nextTaskId_);
    }
    int64_t delayMs = std::max(fireAtMs - GetSystemTime(), static_cast<int64_t>(0));
    nextFireTimeMs_ = fireAtMs;
    // One-shot form (delay first); the next round is scheduled in FlushDueEntries,
    // so no repeated task leaks and the fire time always follows entry due times.
    nextTaskId_ = executors_->Schedule(std::chrono::milliseconds(delayMs), [this]() { InvokeData(); });
}

int64_t DataShareAccessReporter::DueTimeMsLocked(const AccessStatInfo &info) const
{
    int32_t hours = std::min(info.reportIntervalHours * overflowFactor_, MAX_REPORT_INTERVAL_HOURS);
    return info.windowStartTime + static_cast<int64_t>(hours) * MILLISECONDS_PER_HOUR;
}

void DataShareAccessReporter::ReportInBatches(std::vector<AccessStatInfo> &stats)
{
    std::vector<AccessStatInfo> batch;
    for (auto &info : stats) {
        batch.push_back(info);
        if (batch.size() >= MAX_REPORT_BATCH) {
            ReportBatch(batch);
            batch.clear();
        }
    }
    if (!batch.empty()) {
        ReportBatch(batch);
    }
}

void DataShareAccessReporter::ReportBatch(std::vector<AccessStatInfo> &batch)
{
    uint32_t count = static_cast<uint32_t>(batch.size());
    std::vector<std::string> uriHolder(count);
    std::vector<std::string> providerHolder(count);
    std::vector<std::string> callerHolder(count);
    std::vector<std::string> interfaceHolder(count);
    std::vector<int64_t> counts(count);
    std::vector<char *> uris(count);
    std::vector<char *> providers(count);
    std::vector<char *> callers(count);
    std::vector<char *> interfaces(count);
    for (uint32_t i = 0; i < count; i++) {
        uriHolder[i] = AnonymousUri(batch[i].uri);
        providerHolder[i] = batch[i].providerBundleName;
        callerHolder[i] = batch[i].callerBundleName;
        interfaceHolder[i] = GetInterfaceName(batch[i].funcId);
        counts[i] = static_cast<int64_t>(batch[i].count);
        uris[i] = const_cast<char *>(uriHolder[i].c_str());
        providers[i] = const_cast<char *>(providerHolder[i].c_str());
        callers[i] = const_cast<char *>(callerHolder[i].c_str());
        interfaces[i] = const_cast<char *>(interfaceHolder[i].c_str());
    }
    HiSysEventParam uri = {
        .name = "URI", .t = HISYSEVENT_STRING_ARRAY, .v = { .array = uris.data() }, .arraySize = count
    };
    HiSysEventParam provider = { .name = "PROVIDER_BUNDLE_NAME",
        .t = HISYSEVENT_STRING_ARRAY,
        .v = { .array = providers.data() },
        .arraySize = count };
    HiSysEventParam caller = {
        .name = "CALLER_BUNDLE_NAME", .t = HISYSEVENT_STRING_ARRAY, .v = { .array = callers.data() }, .arraySize = count
    };
    HiSysEventParam interface = {
        .name = "INTERFACE_ID", .t = HISYSEVENT_STRING_ARRAY, .v = { .array = interfaces.data() }, .arraySize = count
    };
    HiSysEventParam countParam = {
        .name = "COUNT", .t = HISYSEVENT_INT64_ARRAY, .v = { .array = counts.data() }, .arraySize = count
    };
    HiSysEventParam params[] = { uri, provider, caller, interface, countParam };
    int res = OH_HiSysEvent_Write(DOMAIN, ACCESS_EVENT_NAME, HISYSEVENT_STATISTIC, params, ACCESS_PARAMS_SIZE);
    ZLOGI("OH_HiSysEvent_Write access statistic, res = %{public}d, batch = %{public}u", res, count);
}
} // namespace DataShare
} // namespace OHOS