/**
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

#ifndef OHOS_DISTRIBUTED_DATA_OBSERVER_CACHE_TEST_HELPER_H
#define OHOS_DISTRIBUTED_DATA_OBSERVER_CACHE_TEST_HELPER_H

#include <condition_variable>
#include <future>
#include <thread>

#include "general_store_mock.h"
#include "store/auto_cache.h"

namespace OHOS::DistributedData::Test {
struct CloseGate {
    static constexpr uint32_t WAIT_SECONDS = 3;
    std::mutex mutex;
    std::condition_variable condition;
    bool entered = false;
    bool released = false;

    void Release()
    {
        std::lock_guard<std::mutex> lock(mutex);
        released = true;
        condition.notify_all();
    }

    bool WaitEntered()
    {
        std::unique_lock<std::mutex> lock(mutex);
        return condition.wait_for(lock, std::chrono::seconds(WAIT_SECONDS), [this]() { return entered; });
    }
};

// Owns only a fake store. Restore the complete creator configuration after closing its delegate.
class ObserverCache final {
public:
    ObserverCache(int32_t type, uint32_t tokenId, AutoCache::WatcherFactory watcherFactory)
    {
        meta.storeType = type;
        meta.tokenId = tokenId;
        meta.user = "0";
        meta.area = GeneralStore::EL1;
        meta.storeId = "observer_cache_test";
        {
            auto &cache = AutoCache::GetInstance();
            std::lock_guard<std::mutex> lock(cache.factoryMutex_);
            saved_ = cache.factories_[type];
        }
        ON_CALL(store_, AddRef()).WillByDefault(testing::Return(1));
        ON_CALL(store_, Release()).WillByDefault(testing::Return(1));
        ON_CALL(store_, Watch(testing::_, testing::_)).WillByDefault([this](int32_t, GeneralWatcher &value) {
            watcher = &value;
            return GeneralError::E_OK;
        });
        ON_CALL(store_, Close(testing::_)).WillByDefault([gate = gate_](bool force) {
            if (!force) {
                std::unique_lock<std::mutex> lock(gate->mutex);
                gate->entered = true;
                gate->condition.notify_all();
                gate->condition.wait(lock, [gate]() { return gate->released; });
            }
            return GeneralError::E_OK;
        });
        registration = AutoCache::GetInstance().RegCreator(
            type,
            [this](const StoreMetaData &, const AutoCache::StoreOption &) {
                return std::pair<int32_t, GeneralStore *>{ GeneralError::E_OK, &store_ };
            },
            std::move(watcherFactory));
    }

    ~ObserverCache()
    {
        FinishClose();
        AutoCache::GetInstance().CloseStore([meta = meta](const StoreMetaData &value) {
            return value.tokenId == meta.tokenId && value.storeType == meta.storeType;
        });
        AutoCache::GetInstance().RegCreator(meta.storeType, saved_.creator, saved_.watcherFactory);
    }

    void StartClose()
    {
        closeThread_ = std::thread(
            [meta = meta]() { AutoCache::GetInstance().CloseStore(meta.tokenId, meta.dataDir, meta.storeId); });
    }

    void FinishClose()
    {
        gate_->Release();
        if (closeThread_.joinable()) {
            closeThread_.join();
        }
    }

    bool WaitCloseEntered()
    {
        return gate_->WaitEntered();
    }

    ObserverCache(const ObserverCache &) = delete;
    ObserverCache &operator=(const ObserverCache &) = delete;
    ObserverCache(ObserverCache &&) = delete;
    ObserverCache &operator=(ObserverCache &&) = delete;

    StoreMetaData meta;
    GeneralWatcher *watcher = nullptr;
    int32_t registration = GeneralError::E_ERROR;

private:
    AutoCache::StoreFactory saved_;
    testing::NiceMock<GeneralStoreMock> store_;
    std::shared_ptr<CloseGate> gate_ = std::make_shared<CloseGate>();
    std::thread closeThread_;
};
} // namespace OHOS::DistributedData::Test
#endif // OHOS_DISTRIBUTED_DATA_OBSERVER_CACHE_TEST_HELPER_H
