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

#define LOG_TAG "DelayDataPrepareContainer"
#include "delay_data_prepare_container.h"
#include "log_print.h"

namespace OHOS {
namespace UDMF {
constexpr uint32_t WAIT_TIME = 800;
namespace {
DelayLoadStatus ReadDelayDelivery(const std::optional<DelayDeliveryResult> &dataOpt, UnifiedData &unifiedData)
{
    if (dataOpt.has_value()) {
        if (dataOpt->status != E_OK) {
            if (dataOpt->status == E_NO_PERMISSION) {
                return DelayLoadStatus::NO_PERMISSION;
            }
            return dataOpt->status == E_INVALID_PARAMETERS ? DelayLoadStatus::INVALID_PARAMETERS
                                                           : DelayLoadStatus::LOAD_ERROR;
        }
        unifiedData = dataOpt->data;
        // The receiver consumes the cache only after access checks and authorization succeed.
        return dataOpt->prepared ? DelayLoadStatus::DATA_READY_PREPARED : DelayLoadStatus::DATA_READY;
    }
    return DelayLoadStatus::WAITING;
}
} // namespace

DelayDataPrepareContainer &DelayDataPrepareContainer::GetInstance()
{
    static DelayDataPrepareContainer instance;
    return instance;
}

DelayLoadStatus DelayDataPrepareContainer::GetOrCreateDelivery(
    const QueryOption &query, BlockDelayData &delivery, sptr<IUdmfNotifier> &callback)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    if (dataLoadCallback_.find(query.key) == dataLoadCallback_.end()) {
        return DelayLoadStatus::NOT_DELAY_DATA;
    }
    auto it = blockDelayDataCache_.find(query.key);
    if (it != blockDelayDataCache_.end() && it->second.tokenId != query.tokenId) {
        return DelayLoadStatus::NO_PERMISSION;
    }
    if (it == blockDelayDataCache_.end()) {
        auto block =
            std::make_shared<BlockData<std::optional<DelayDeliveryResult>, std::chrono::milliseconds>>(WAIT_TIME);
        if (!BeginDataLoadLocked(query.key, 0, callback, true)) {
            return DelayLoadStatus::LOAD_ERROR;
        }
        BlockDelayData pending{ query.tokenId, block, 0, origins_.at(query.key).load };
        it = blockDelayDataCache_.emplace(query.key, std::move(pending)).first;
    }
    delivery = it->second;
    return DelayLoadStatus::WAITING;
}

DelayLoadStatus DelayDataPrepareContainer::HandleDelayLoad(
    const QueryOption &query, UnifiedData &unifiedData, BlockDelayData *delivery)
{
    PurgeExpired();
    if (query.key.empty()) {
        return DelayLoadStatus::NOT_DELAY_DATA;
    }
    sptr<IUdmfNotifier> callback;
    BlockDelayData current;
    auto status = GetOrCreateDelivery(query, current, callback);
    if (status != DelayLoadStatus::WAITING) {
        return status;
    }
    if (delivery != nullptr) {
        *delivery = current;
    }
    if (callback != nullptr) {
        callback->HandleDelayObserver(query.key, DataLoadInfo());
    }
    return current.blockData ? ReadDelayDelivery(current.blockData->GetValue(), unifiedData)
                             : DelayLoadStatus::LOAD_ERROR;
}

bool DelayDataPrepareContainer::RegisterDataLoadCallback(
    const std::string &key, sptr<IUdmfNotifier> callback, uint32_t sourceTokenId, LoadToken *registered)
{
    PurgeExpired();
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    if (key.empty() || callback == nullptr || (origins_.count(key) == 0 && origins_.size() >= MAX_DELAY_ENTRIES)) {
        return false;
    }
    EraseBlockLocked(key);
    dataLoadCallback_.insert_or_assign(key, callback);
    LoadToken token{ ++nextGeneration_, 0 };
    origins_.insert_or_assign(key, OriginInfo{ Clock::now() + DELIVERY_LIFETIME, sourceTokenId, token });
    if (registered != nullptr) {
        *registered = token;
    }
    return true;
}

bool DelayDataPrepareContainer::MatchesOriginLocked(const std::string &key, const LoadToken &expected) const
{
    auto it = origins_.find(key);
    return it != origins_.end() && expected.generation != 0 && it->second.load.generation == expected.generation &&
           it->second.load.loadId == expected.loadId;
}

bool DelayDataPrepareContainer::QueryDataLoadToken(const std::string &key, LoadToken &token)
{
    PurgeExpired();
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    auto it = origins_.find(key);
    if (it == origins_.end()) {
        return false;
    }
    token = it->second.load;
    return true;
}

bool DelayDataPrepareContainer::CompleteDataLoad(const std::string &key, const LoadToken &expected)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    if (!MatchesOriginLocked(key, expected)) {
        return false;
    }
    EraseBlockLocked(key);
    dataLoadCallback_.erase(key);
    origins_.erase(key);
    return true;
}

bool DelayDataPrepareContainer::ReleaseDataLoad(const std::string &key, const LoadToken &expected)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    if (!MatchesOriginLocked(key, expected)) {
        return false;
    }
    origins_.at(key).loading = false;
    return true;
}

int DelayDataPrepareContainer::QueryDataLoadCallbackSize()
{
    PurgeExpired();
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    return static_cast<int>(dataLoadCallback_.size());
}

bool DelayDataPrepareContainer::BeginDataLoadLocked(
    const std::string &key, uint64_t requestId, sptr<IUdmfNotifier> &callback, bool force)
{
    auto it = dataLoadCallback_.find(key);
    auto origin = origins_.find(key);
    if (it == dataLoadCallback_.end() || it->second == nullptr || origin == origins_.end()) {
        return false;
    }
    auto &state = origin->second;
    if (!force && state.loading && state.requestId == requestId) {
        return true;
    }
    state.loading = true;
    state.requestId = requestId;
    state.load.loadId = ++nextLoadId_;
    callback = it->second;
    return true;
}

bool DelayDataPrepareContainer::ExecDataLoadCallback(
    const std::string &key, const DataLoadInfo &info, uint64_t requestId)
{
    PurgeExpired();
    sptr<IUdmfNotifier> callback;
    {
        std::lock_guard<std::mutex> lock(dataLoadMutex_);
        if (!BeginDataLoadLocked(key, requestId, callback)) {
            return false;
        }
    }
    if (callback != nullptr) {
        callback->HandleDelayObserver(key, info);
    }
    return true;
}

void DelayDataPrepareContainer::ExecAllDataLoadCallback()
{
    PurgeExpired();
    std::vector<std::string> keys;
    {
        std::lock_guard<std::mutex> lock(dataLoadMutex_);
        for (auto it = dataLoadCallback_.begin(); it != dataLoadCallback_.end();) {
            if (it->second == nullptr) {
                it = dataLoadCallback_.erase(it);
                continue;
            }
            keys.push_back(it->first);
            ++it;
        }
    }
    for (const auto &key : keys) {
        ExecDataLoadCallback(key, DataLoadInfo());
    }
}

bool DelayDataPrepareContainer::QueryBlockDelayData(const std::string &key, BlockDelayData &blockData)
{
    PurgeExpired();
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    auto it = blockDelayDataCache_.find(key);
    if (it == blockDelayDataCache_.end()) {
        return false;
    }
    blockData = it->second;
    return true;
}

void DelayDataPrepareContainer::EraseBlockLocked(const std::string &key)
{
    auto it = blockDelayDataCache_.find(key);
    if (it != blockDelayDataCache_.end()) {
        cachedBytes_ -= it->second.cachedBytes;
        blockDelayDataCache_.erase(it);
    }
}

bool DelayDataPrepareContainer::CompleteDelayLoad(
    const std::string &key, uint32_t tokenId, const BlockDelayData *expected)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    auto it = blockDelayDataCache_.find(key);
    if (it == blockDelayDataCache_.end() || it->second.tokenId != tokenId ||
        (expected != nullptr && expected->blockData != it->second.blockData)) {
        return false;
    }
    const auto origin = it->second.origin;
    EraseBlockLocked(key);
    if (MatchesOriginLocked(key, origin)) {
        dataLoadCallback_.erase(key);
        origins_.erase(key);
    }
    return true;
}

bool DelayDataPrepareContainer::ReleaseDelivery(const std::string &key, const BlockDelayData &expected)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    auto it = blockDelayDataCache_.find(key);
    if (it == blockDelayDataCache_.end() || it->second.tokenId != expected.tokenId ||
        it->second.blockData != expected.blockData) {
        return false;
    }
    EraseBlockLocked(key);
    if (MatchesOriginLocked(key, expected.origin)) {
        origins_.at(key).loading = false;
    }
    return true;
}

bool DelayDataPrepareContainer::StoreDelivery(
    const std::string &key, const BlockDelayData &expected, DelayDeliveryResult result)
{
    const auto bytes = result.data.GetSize();
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    auto it = blockDelayDataCache_.find(key);
    if (it == blockDelayDataCache_.end() || it->second.blockData != expected.blockData ||
        it->second.tokenId != expected.tokenId || !expected.blockData) {
        return false;
    }
    const auto available = UnifiedData::MAX_DATA_SIZE - (cachedBytes_ - it->second.cachedBytes);
    const bool fits = bytes >= 0 && bytes <= available;
    cachedBytes_ -= it->second.cachedBytes;
    it->second.cachedBytes = fits ? bytes : 0;
    cachedBytes_ += it->second.cachedBytes;
    expected.blockData->SetValue(fits ? std::move(result) : DelayDeliveryResult{ UnifiedData(), E_ERROR, false });
    return fits;
}

void DelayDataPrepareContainer::Remove(const std::string &key)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    EraseBlockLocked(key);
    dataLoadCallback_.erase(key);
    origins_.erase(key);
}

void DelayDataPrepareContainer::RemoveByToken(uint32_t tokenId)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    for (auto it = origins_.begin(); it != origins_.end();) {
        auto block = blockDelayDataCache_.find(it->first);
        if (it->second.tokenId == tokenId ||
            (block != blockDelayDataCache_.end() && block->second.tokenId == tokenId)) {
            EraseBlockLocked(it->first);
            dataLoadCallback_.erase(it->first);
            it = origins_.erase(it);
        } else {
            ++it;
        }
    }
}

void DelayDataPrepareContainer::PurgeExpired(Clock::time_point now)
{
    std::lock_guard<std::mutex> lock(dataLoadMutex_);
    for (auto it = origins_.begin(); it != origins_.end();) {
        if (it->second.expires <= now) {
            EraseBlockLocked(it->first);
            dataLoadCallback_.erase(it->first);
            it = origins_.erase(it);
        } else {
            ++it;
        }
    }
}

void DelayDataPrepareContainer::BindExecutor(const std::shared_ptr<ExecutorPool> &executors)
{
    std::shared_ptr<ExecutorPool> previous;
    ExecutorPool::TaskId previousTask;
    {
        std::lock_guard<std::mutex> lock(dataLoadMutex_);
        previous = executors_.lock();
        if (previous == executors) {
            return;
        }
        previousTask = purgeTask_;
        executors_ = executors;
        purgeTask_ =
            executors ? executors->Schedule([] { GetInstance().PurgeExpired(); }, DELIVERY_LIFETIME, DELIVERY_LIFETIME)
                      : ExecutorPool::INVALID_TASK_ID;
    }
    if (previous) {
        previous->Remove(previousTask);
    }
}

} // namespace UDMF
} // namespace OHOS
