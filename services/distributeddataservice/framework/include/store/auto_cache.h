/**
 * Copyright (c) 2023-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_STORE_AUTO_CACHE_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_STORE_AUTO_CACHE_H
#include <list>
#include <memory>
#include <set>
#include <shared_mutex>

#include "concurrent_map.h"
#include "concurrent_striped_map.h"
#include "error/general_error.h"
#include "executor_pool.h"
#include "metadata/store_meta_data.h"
#include "store/general_store.h"
#include "store/general_value.h"
#include "store/general_watcher.h"
#include "store/watcher_bridge.h"
#include "visibility.h"
namespace OHOS::DistributedData {
class SchemaMeta;
class AutoCache {
public:
    struct StoreOption {
        bool createRequired = false;
        bool isEnableBinlog = false;
    };
    using Error = GeneralError;
    using Store = std::shared_ptr<GeneralStore>;
    using Stores = std::list<std::shared_ptr<GeneralStore>>;
    using Watcher = GeneralWatcher;
    using Watchers = std::set<std::shared_ptr<GeneralWatcher>>;
    using Time = std::chrono::steady_clock::time_point;
    using Executor = ExecutorPool;
    using TaskId = ExecutorPool::TaskId;
    using Creator = std::function<std::pair<int32_t, GeneralStore *>(const StoreMetaData &, const StoreOption &)>;
    using WatcherFactory = std::function<WatcherBridge::Getter(const StoreMetaData &)>;
    using Filter = std::function<bool(const StoreMetaData &)>;

    API_EXPORT static AutoCache &GetInstance();

    API_EXPORT void Configure(uint32_t garbageInterval);

    API_EXPORT int32_t RegCreator(int32_t type, Creator creator);

    // The factory creates a getter without querying subscriptions or opening a store.
    // Delegate owns the forwarding bridge; an empty getter means no client subscriptions.
    API_EXPORT int32_t RegWatcherFactory(int32_t type, WatcherFactory watcherFactory);

    API_EXPORT void Bind(std::shared_ptr<Executor> executor);

    API_EXPORT Store GetStore(const StoreMetaData &meta);

    API_EXPORT std::pair<int32_t, Store> GetDBStore(const StoreMetaData &meta,
        const StoreOption &option = { false, false });

    API_EXPORT Stores GetStoresIfPresent(
        uint32_t tokenId, const std::string &path = "", const std::string &storeId = "");

    API_EXPORT void CloseStore(uint32_t tokenId, const std::string &path = "", const std::string &storeId = "");
 
    API_EXPORT void CloseStore(const Filter &filter);
 
    API_EXPORT void Enable(uint32_t tokenId, const std::string &path = "", const std::string &storeId = "");
 
    API_EXPORT void Disable(uint32_t tokenId, const std::string &path = "", const std::string &storeId = "");

private:
    AutoCache();
    ~AutoCache();
    std::string GenerateKey(const std::string &path, const std::string &storeId) const;
    void GarbageCollect(bool isForce);
    void StartTimer();
    static int32_t CheckStatusBeforeOpen(const StoreMetaData &meta);
    WatcherBridge::Getter GetWatcher(const StoreMetaData &meta) const;
    struct Delegate : public GeneralWatcher {
        Delegate(GeneralStore *delegate, WatcherBridge::Getter getter, const StoreMetaData &meta,
            uint32_t garbageInterval = DEFAULT_INTERVAL);
        ~Delegate();
        operator Store();
        bool operator<(const Time &time) const;
        bool Close();
        int32_t GetArea() const;
        const StoreMetaData &GetMeta() const;
        int32_t OnChange(const Origin &origin, const PRIFields &primaryFields, ChangeInfo &&values) override;
        int32_t OnChange(const Origin &origin, const Fields &fields, ChangeData &&datas) override;
        void PostDataChange(const StoreMetaData &meta, const std::vector<std::string> &tables);

    private:
        mutable Time time_;
        GeneralStore *store_ = nullptr;
        WatcherBridge watcher_;
        const StoreMetaData meta_;
        const uint32_t garbageInterval_;
    };
    static constexpr uint32_t DEFAULT_INTERVAL = 60 * 1000;
    static constexpr int32_t MAX_CREATOR_NUM = 30;

    uint32_t garbageInterval_ = DEFAULT_INTERVAL;
    std::shared_ptr<Executor> executor_;
    TaskId taskId_ = Executor::INVALID_TASK_ID;
    ConcurrentStripedMap<uint32_t, std::map<std::string, Delegate>> stores_;
    ConcurrentMap<uint32_t, std::set<std::string>> disables_;
    Creator creators_[MAX_CREATOR_NUM];
    mutable std::shared_mutex watcherMutex_;
    WatcherFactory watcherFactories_[MAX_CREATOR_NUM];
};
} // namespace OHOS::DistributedData
#endif // OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_STORE_AUTO_CACHE_H
