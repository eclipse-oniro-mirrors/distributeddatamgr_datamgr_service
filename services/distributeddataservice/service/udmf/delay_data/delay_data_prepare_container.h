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

#ifndef UDMF_DELAY_DATA_PREPARE_CONTAINER_H
#define UDMF_DELAY_DATA_PREPARE_CONTAINER_H

#include "block_data.h"
#include "error_code.h"
#include "executor_pool.h"
#include "udmf_notifier_proxy.h"
#include "unified_data.h"

namespace OHOS {
namespace UDMF {
struct DelayDeliveryResult {
    UnifiedData data;
    int32_t status = E_OK;
    bool prepared = false;
};
// Identifies both the source registration and one fetch from that source.
struct DelayDataLoadToken {
    uint64_t generation = 0;
    uint64_t loadId = 0;
};
struct BlockDelayData {
    uint32_t tokenId {0};
    std::shared_ptr<BlockData<std::optional<DelayDeliveryResult>, std::chrono::milliseconds>> blockData;
    int64_t cachedBytes = 0;
    DelayDataLoadToken origin;
};

enum class DelayLoadStatus {
    NOT_DELAY_DATA = 0,
    WAITING,
    DATA_READY,
    DATA_READY_PREPARED,
    INVALID_PARAMETERS,
    NO_PERMISSION,
    LOAD_ERROR,
};

class DelayDataPrepareContainer {
public:
    static DelayDataPrepareContainer &GetInstance();
    // dataLoadCallback_ part
    using Clock = std::chrono::steady_clock;
    using LoadToken = DelayDataLoadToken;
    void BindExecutor(const std::shared_ptr<ExecutorPool> &executors);
    void PurgeExpired(Clock::time_point now = Clock::now());
    void Remove(const std::string &key);
    void RemoveByToken(uint32_t tokenId);
    DelayLoadStatus HandleDelayLoad(
        const QueryOption &query, UnifiedData &unifiedData, BlockDelayData *delivery = nullptr);
    bool RegisterDataLoadCallback(const std::string &key, sptr<IUdmfNotifier> callback, uint32_t sourceTokenId = 0,
        LoadToken *registered = nullptr);
    bool QueryDataLoadToken(const std::string &key, LoadToken &token);
    bool CompleteDataLoad(const std::string &key, const LoadToken &expected);
    bool ReleaseDataLoad(const std::string &key, const LoadToken &expected);
    int QueryDataLoadCallbackSize();
    bool ExecDataLoadCallback(const std::string &key, const DataLoadInfo &info, uint64_t requestId = 0);
    void ExecAllDataLoadCallback();

    // blockDelayDataCache_ part
    bool QueryBlockDelayData(const std::string &key, BlockDelayData &getDataInfo);
    bool CompleteDelayLoad(const std::string &key, uint32_t tokenId, const BlockDelayData *expected = nullptr);
    bool ReleaseDelivery(const std::string &key, const BlockDelayData &expected);
    bool StoreDelivery(const std::string &key, const BlockDelayData &expected, DelayDeliveryResult result);

private:
    DelayDataPrepareContainer() = default;
    ~DelayDataPrepareContainer() = default;
    DelayDataPrepareContainer(const DelayDataPrepareContainer &obj) = delete;
    DelayDataPrepareContainer &operator=(const DelayDataPrepareContainer &obj) = delete;

    void EraseBlockLocked(const std::string &key);
    bool MatchesOriginLocked(const std::string &key, const LoadToken &expected) const;
    bool BeginDataLoadLocked(
        const std::string &key, uint64_t requestId, sptr<IUdmfNotifier> &callback, bool force = false);
    DelayLoadStatus GetOrCreateDelivery(
        const QueryOption &query, BlockDelayData &delivery, sptr<IUdmfNotifier> &callback);
    struct OriginInfo {
        Clock::time_point expires;
        uint32_t tokenId;
        LoadToken load;
        uint64_t requestId = 0;
        bool loading = false;
    };
    static constexpr size_t MAX_DELAY_ENTRIES = 128;
    static constexpr std::chrono::seconds DELIVERY_LIFETIME{ 30 };
    std::map<std::string, OriginInfo> origins_;
    uint64_t nextGeneration_ = 0;
    uint64_t nextLoadId_ = 0;
    int64_t cachedBytes_ = 0;
    std::weak_ptr<ExecutorPool> executors_;
    ExecutorPool::TaskId purgeTask_ = ExecutorPool::INVALID_TASK_ID;
    std::mutex dataLoadMutex_;
    std::map<std::string, sptr<IUdmfNotifier>> dataLoadCallback_ {};
    std::map<std::string, BlockDelayData> blockDelayDataCache_ {};
};
} // namespace UDMF
} // namespace OHOS
#endif // UDMF_DELAY_DATA_PREPARE_CONTAINER_H
