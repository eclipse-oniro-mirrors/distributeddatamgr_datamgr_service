/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#define LOG_TAG "SchedulerManager"

#include "scheduler_manager.h"

#include <cinttypes>

#include "log_print.h"
#include "timer_info.h"
#include "uri_utils.h"
#include "utils/anonymous.h"
#include "log_debug.h"

namespace OHOS::DataShare {
static constexpr int64_t MAX_MILLISECONDS = 31536000000; // 365 days
static constexpr int32_t DELAYED_MILLISECONDS = 200;
SchedulerManager &SchedulerManager::GetInstance()
{
    static SchedulerManager instance;
    return instance;
}

void SchedulerManager::Execute(const std::string &uri, const int32_t userId, DistributedData::StoreMetaData &metaData)
{
    if (!URIUtils::IsDataProxyURI(uri)) {
        return;
    }
    metaData.user = std::to_string(userId);
    auto delegate = DBDelegate::Create(metaData);
    if (delegate == nullptr) {
        ZLOGE("malloc fail %{public}s", URIUtils::Anonymous(uri).c_str());
        return;
    }
    std::vector<Key> keys = RdbSubscriberManager::GetInstance().GetKeysByUri(uri);
    for (auto const &key : keys) {
        ExecuteSchedulerSQL(userId, metaData, key, delegate);
    }
}

void SchedulerManager::Execute(const Key &key, const int32_t userId, const DistributedData::StoreMetaData &metaData)
{
    DistributedData::StoreMetaData meta = metaData;
    meta.bundleName = key.bundleName;
    meta.user = std::to_string(userId);
    auto delegate = DBDelegate::Create(meta);
    if (delegate == nullptr) {
        ZLOGE("malloc fail %{public}s", URIUtils::Anonymous(key.uri).c_str());
        return;
    }
    ExecuteSchedulerSQL(userId, meta, key, delegate);
}

void SchedulerManager::Start(const Key &key, int32_t userId, const DistributedData::StoreMetaData &metaData)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = schedulerStatusCache_.find(key);
        if (it == schedulerStatusCache_.end()) {
            schedulerStatusCache_.emplace(key, true);
        }
    }
    Execute(key, userId, metaData);
}

void SchedulerManager::Stop(const Key &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    RemoveTimer(key);
    auto it = schedulerStatusCache_.find(key);
    if (it != schedulerStatusCache_.end()) {
        schedulerStatusCache_.erase(it);
    }
}

void SchedulerManager::Enable(const Key &key, int32_t userId, const DistributedData::StoreMetaData &metaData)
{
    Template tpl;
    if (!TemplateManager::GetInstance().Get(key, userId, tpl) ||
        tpl.scheduler_.empty() || tpl.scheduler_.find(REMIND_TIMER_FUNC) == std::string::npos) {
        ZLOGE("find template scheduler failed, %{public}s, %{public}" PRId64 ", %{public}s",
            URIUtils::Anonymous(key.uri).c_str(), key.subscriberId, key.bundleName.c_str());
        return;
    }
    bool isTimerStopped = false;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = schedulerStatusCache_.find(key);
        if (it != schedulerStatusCache_.end()) {
            it->second = true;
        }
        auto timer = timerCache_.find(key);
        if (timer == timerCache_.end()) {
            isTimerStopped = true;
        }
    }
    if (isTimerStopped) {
        Execute(key, userId, metaData);
        RdbSubscriberManager::GetInstance().EmitByKey(key, userId, metaData);
    }
}

void SchedulerManager::Disable(const Key &key)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = schedulerStatusCache_.find(key);
    if (it != schedulerStatusCache_.end()) {
        it->second = false;
    }
}

bool SchedulerManager::SetTimerTask(uint64_t &timerId, const std::function<void()> &callback,
    int64_t reminderTime)
{
    auto timerInfo = std::make_shared<TimerInfo>();
    timerInfo->SetType(timerInfo->TIMER_TYPE_EXACT);
    timerInfo->SetRepeat(false);
    auto wantAgent = std::shared_ptr<AbilityRuntime::WantAgent::WantAgent>();
    timerInfo->SetWantAgent(wantAgent);
    timerInfo->SetCallbackInfo(callback);
    timerId = TimeServiceClient::GetInstance()->CreateTimer(timerInfo);
    if (timerId == 0) {
        return false;
    }
    TimeServiceClient::GetInstance()->StartTimer(timerId, static_cast<uint64_t>(reminderTime));
    return true;
}

void SchedulerManager::DestoryTimerTask(int64_t timerId)
{
    if (timerId > 0) {
        TimeServiceClient::GetInstance()->DestroyTimer(timerId);
    }
}

void SchedulerManager::ResetTimerTask(int64_t timerId, int64_t reminderTime)
{
    // This start also means reset, new one will replace old one
    TimeServiceClient::GetInstance()->StartTimer(timerId, static_cast<uint64_t>(reminderTime));
}

int64_t SchedulerManager::EraseTimerTaskId(const Key &key)
{
    int64_t timerId = -1;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = timerCache_.find(key);
    if (it != timerCache_.end()) {
        timerId = it->second;
        timerCache_.erase(key);
    }
    return timerId;
}

bool SchedulerManager::GetSchedulerStatus(const Key &key)
{
    bool enabled = false;
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = schedulerStatusCache_.find(key);
    if (it != schedulerStatusCache_.end()) {
        enabled = it->second;
    }
    return enabled;
}

void SchedulerManager::SetTimer(
    const int32_t userId, DistributedData::StoreMetaData &metaData, const Key &key, int64_t reminderTime)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (executor_ == nullptr) {
        ZLOGE("executor_ is nullptr");
        return;
    }
    int64_t now = 0;
    TimeServiceClient::GetInstance()->GetWallTimeMs(now);
    if (reminderTime <= now || reminderTime - now >= MAX_MILLISECONDS) {
        ZLOGE("invalid args, %{public}" PRId64 ", %{public}" PRId64 ", subId=%{public}" PRId64
            ", bundleName=%{public}s.", reminderTime, now, key.subscriberId, key.bundleName.c_str());
        return;
    }
    auto duration = reminderTime - now;
    ZLOGI("the task will notify in %{public}" PRId64 " ms, %{public}" PRId64 ", %{public}s.",
          duration, key.subscriberId, key.bundleName.c_str());
    auto it = timerCache_.find(key);
    if (it != timerCache_.end()) {
        ZLOGD_MACRO("has current taskId: %{private}s, subscriberId is %{public}" PRId64 ", bundleName is %{public}s",
            URIUtils::Anonymous(key.uri).c_str(), key.subscriberId, key.bundleName.c_str());
        auto timerId = it->second;
        ResetTimerTask(timerId, reminderTime);
        return;
    }
    auto callback = [key, metaData, userId, this]() {
        ZLOGI("schedule notify start, uri is %{private}s, subscriberId is %{public}" PRId64 ", bundleName is "
            "%{public}s", URIUtils::Anonymous(key.uri).c_str(),
            key.subscriberId, key.bundleName.c_str());
        int64_t timerId = EraseTimerTaskId(key);
        DestoryTimerTask(timerId);
        if (GetSchedulerStatus(key)) {
            Execute(key, userId, metaData);
            RdbSubscriberManager::GetInstance().EmitByKey(key, userId, metaData);
        }
    };
    uint64_t timerId = 0;
    if (!SetTimerTask(timerId, callback, reminderTime)) {
        ZLOGE("create timer failed.");
        return;
    }
    ZLOGI("create new task success, uri is %{public}s, subscriberId is %{public}" PRId64 ", bundleName is %{public}s",
        URIUtils::Anonymous(key.uri).c_str(), key.subscriberId, key.bundleName.c_str());
    timerCache_.emplace(key, timerId);
}

void SchedulerManager::ExecuteSchedulerSQL(const int32_t userId, DistributedData::StoreMetaData &metaData,
    const Key &key, std::shared_ptr<DBDelegate> delegate)
{
    Template tpl;
    if (!TemplateManager::GetInstance().Get(key, userId, tpl)) {
        ZLOGE("template undefined, %{public}s, %{public}" PRId64 ", %{public}s",
            URIUtils::Anonymous(key.uri).c_str(), key.subscriberId, key.bundleName.c_str());
        return;
    }
    if (tpl.scheduler_.empty()) {
        ZLOGW("template scheduler_ empty, %{public}s, %{public}" PRId64 ", %{public}s",
            URIUtils::Anonymous(key.uri).c_str(), key.subscriberId, key.bundleName.c_str());
        return;
    }
    GenRemindTimerFuncParams(userId, metaData, key, tpl.scheduler_);
    auto resultSet = delegate->QuerySql(tpl.scheduler_);
    if (resultSet == nullptr) {
        ZLOGE("resultSet is nullptr, %{public}s, %{public}" PRId64 ", %{public}s",
            URIUtils::Anonymous(key.uri).c_str(), key.subscriberId, key.bundleName.c_str());
        return;
    }
    int count;
    int errCode = resultSet->GetRowCount(count);
    if (errCode != E_OK || count == 0) {
        ZLOGE("GetRowCount error, %{public}s, %{public}" PRId64 ", %{public}s, errorCode is %{public}d, count is "
            "%{public}d",
            URIUtils::Anonymous(key.uri).c_str(), key.subscriberId, key.bundleName.c_str(), errCode,
            count);
        return;
    }
}

void SchedulerManager::GenRemindTimerFuncParams(
    const int32_t userId, DistributedData::StoreMetaData &metaData, const Key &key, std::string &schedulerSQL)
{
    auto index = schedulerSQL.find(REMIND_TIMER_FUNC);
    if (index == std::string::npos) {
        ZLOGW("not find remindTimer, sql is %{public}s", URIUtils::Anonymous(schedulerSQL).c_str());
        return;
    }
    index += REMIND_TIMER_FUNC_LEN;
    std::string keyStr = "'" + metaData.dataDir + "', " + std::to_string(metaData.tokenId) + ", '" + key.uri + "', " +
                         std::to_string(key.subscriberId) + ", '" + key.bundleName + "', " + std::to_string(userId) +
                         ", '" + metaData.storeId + "', " + std::to_string(metaData.haMode) + ", ";
    schedulerSQL.insert(index, keyStr);
    return;
}

void SchedulerManager::RemoveTimer(const Key &key)
{
    if (executor_ == nullptr) {
        ZLOGE("executor_ is nullptr");
        return;
    }
    auto it = timerCache_.find(key);
    if (it != timerCache_.end()) {
        ZLOGW("RemoveTimer %{public}s %{public}s %{public}" PRId64,
            URIUtils::Anonymous(key.uri).c_str(), key.bundleName.c_str(), key.subscriberId);
        DestoryTimerTask(it->second);
        timerCache_.erase(key);
    }
}

void SchedulerManager::ClearTimer()
{
    ZLOGI("Clear all timer");
    std::lock_guard<std::mutex> lock(mutex_);
    if (executor_ == nullptr) {
        ZLOGE("executor_ is nullptr");
        return;
    }
    auto it = timerCache_.begin();
    while (it != timerCache_.end()) {
        DestoryTimerTask(it->second);
        it = timerCache_.erase(it);
    }
}

void SchedulerManager::SetExecutorPool(std::shared_ptr<ExecutorPool> executor)
{
    executor_ = executor;
}

void SchedulerManager::ReExecuteAll()
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &item : timerCache_) {
        // restart in 200ms
        auto timerId = item.second;
        int64_t currentTime = 0;
        TimeServiceClient::GetInstance()->GetWallTimeMs(currentTime);
        ResetTimerTask(timerId, currentTime + DELAYED_MILLISECONDS);
    }
}
} // namespace OHOS::DataShare

