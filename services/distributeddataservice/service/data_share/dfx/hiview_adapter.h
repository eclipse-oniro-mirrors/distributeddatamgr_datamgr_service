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

#ifndef DATASHARESERVICE_HIVIEW_ADAPTER_H
#define DATASHARESERVICE_HIVIEW_ADAPTER_H


#include <atomic>
#include <map>
#include <mutex>
#include <string>
#include <utility>

#include "hiview_base_adapter.h"
#include "concurrent_map.h"
#include "data_share_service_stub.h"
namespace OHOS {
namespace DataShare {
struct CallerInfo {
    uint64_t callerTokenId = 0;
    uint64_t callerUid = 0;
    uint64_t callerPid = 0;
    uint64_t costTime = 0;
    bool isSlowRequest = false;
    uint32_t funcId = 0;

    CallerInfo(uint64_t tokenId, uint64_t uid, uint64_t pid, uint64_t time, uint32_t id)
        : callerTokenId(tokenId), callerUid(uid), callerPid(pid), costTime(time), funcId(id)
    {}
};

struct CallerTotalInfo {
    uint64_t callerUid = 0;
    uint64_t totalCount = 0;
    uint64_t slowRequestCount = 0;
    uint64_t maxCostTime = 0;
    uint64_t totalCostTime = 0;
    std::string callerName;
    std::map<std::string, uint64_t> funcCounts;
};

struct AccessStatInfo {
    std::string uri;
    std::string providerBundleName;
    std::string callerBundleName;
    uint32_t funcId = 0;
    uint64_t count = 0;
    // Backfilled from the owning UriEntry on query, not stored per row.
    int64_t windowStartTime = 0;
    int32_t reportIntervalHours = 24;
};

// One statistics entry per uri: the report window and all caller statistics live
// in a single entry, so flushing the entry atomically reports one complete snapshot
// of that uri's configured interval. The enable flag and report interval are
// configured at uri granularity in the provider profile.
struct UriEntry {
    int64_t windowStartTime = 0;
    int32_t reportIntervalHours = 24;
    std::string uri;
    std::string providerBundleName;
    std::map<std::string, std::map<uint32_t, uint64_t>> callers;  // caller → (funcId → count)
};

class HiViewAdapter : public HiViewBaseAdapter {
public:
    static HiViewAdapter &GetInstance();
    void InvokeData() override;
    void ReportDataStatistic(const CallerInfo &callerInfo);

private:
    ConcurrentMap<uint64_t, CallerTotalInfo> callers_;
    std::map<uint32_t, std::string> funcIdMap_ = {
        {static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_QUERY), "OnQuery"},
        {static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_INSERTEX), "OnInsertEx"},
        {static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_DELETEEX), "OnDeleteEx"},
        {static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_UPDATEEX), "OnUpdateEx"},
        {static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_NOTIFY_OBSERVERS), "OnNotifyObserver"},
        {static_cast<uint32_t>(IDataShareService::DATA_SHARE_SERVICE_CMD_GET_SILENT_PROXY_STATUS),
            "OnGetSilentProxyStatus"}
    };
    void GetCallerTotalInfoVec(std::vector<CallerTotalInfo> &callerTotalInfos);
};

class DataShareAccessReporter {
public:
    static DataShareAccessReporter &GetInstance();
    void Record(const std::string &uri, const std::string &providerBundleName,
        const std::string &callerBundleName, uint32_t funcId, int32_t reportIntervalHours);
    void Init(std::shared_ptr<ExecutorPool> executors);
    void FlushAll();
    void FlushDue();
    size_t GetStatsCount();
    bool GetAccessStatInfo(const std::string &uri, const std::string &providerBundleName,
        const std::string &callerBundleName, uint32_t funcId, AccessStatInfo &info);
    static std::string AnonymousUri(const std::string &uri);
    static std::string FormatApiCounts(const std::map<uint32_t, uint64_t> &apiCounts);

private:
    ConcurrentMap<std::string, UriEntry> entries_;
    std::atomic<size_t> rowCount_ { 0 };
    std::shared_ptr<ExecutorPool> executors_;
    std::mutex flushMutex_;
    ExecutorPool::TaskId nextTaskId_ = ExecutorPool::INVALID_TASK_ID;
    int64_t nextFireTimeMs_ = 0;
    std::atomic<bool> overflowFlushPending_ { false };
    std::atomic<int64_t> lastOverflowFlushMs_ { 0 };
    void FlushEntries(bool forceAll);
    bool TryDispatchOverflowFlush();
    void ScheduleLocked(int64_t fireAtMs);
    void CancelTimerLocked();
    int64_t DueTimeMsLocked(const UriEntry &entry) const;
    int64_t NowMs() const;
    void ReportEntry(const UriEntry &entry);
    static std::string MakeUriKey(const std::string &uri, const std::string &providerBundleName);
};
} // namespace DataShare
} // namespace OHOS
#endif // DATASHARESERVICE_HIVIEW_ADAPTER_H