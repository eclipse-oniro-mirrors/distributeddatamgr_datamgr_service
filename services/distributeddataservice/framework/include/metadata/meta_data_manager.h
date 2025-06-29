/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_METADATA_META_DATA_MANAGER_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_METADATA_META_DATA_MANAGER_H
#include <functional>
#include <memory>
#include <mutex>

#include "concurrent_map.h"
#include "serializable/serializable.h"
#include "lru_bucket.h"
namespace DistributedDB {
class KvStoreNbDelegate;
}
namespace OHOS::DistributedData {
class MetaObserver;
class MetaDataManager {
public:
    enum Action : int32_t {
        INSERT,
        UPDATE,
        DELETE,
    };
    class API_EXPORT Filter {
    public:
        Filter() = default;
        Filter(const std::string &pattern);
        virtual ~Filter() = default;
        virtual bool operator()(const std::string &key) const;
        virtual std::vector<uint8_t> GetKey() const;

    private:
        std::string pattern_;
    };
    using MetaStore = DistributedDB::KvStoreNbDelegate;
    using Observer = std::function<bool(const std::string &, const std::string &, int32_t)>;
    using Syncer = std::function<void(const std::shared_ptr<MetaStore> &, int32_t)>;
    using CloudSyncer = std::function<void()>;
    using Backup = std::function<int32_t(const std::shared_ptr<MetaStore> &)>;
    using Bytes = std::vector<uint8_t>;
    using OnComplete = std::function<void(const std::map<std::string, int32_t> &)>;
    struct Entry {
        std::string key;
        std::string value;
    };
    API_EXPORT static MetaDataManager &GetInstance();
    API_EXPORT void Initialize(std::shared_ptr<MetaStore> metaStore, const Backup &backup, const std::string &storeId);
    API_EXPORT void SetSyncer(const Syncer &syncer);
    API_EXPORT void SetCloudSyncer(const CloudSyncer &cloudSyncer);
    API_EXPORT bool SaveMeta(const std::string &key, const Serializable &value, bool isLocal = false);
    API_EXPORT bool SaveMeta(const std::vector<Entry> &values, bool isLocal = false);
    API_EXPORT bool LoadMeta(const std::string &key, Serializable &value, bool isLocal = false);
    template<class T>
    API_EXPORT bool LoadMeta(const std::string &prefix, std::vector<T> &values, bool isLocal = false)
    {
        if (!inited_) {
            return false;
        }
        std::vector<Bytes> entries;
        if (!GetEntries(prefix, entries, isLocal)) {
            return false;
        }
        values.resize(entries.size());
        for (size_t i = 0; i < entries.size(); ++i) {
            Serializable::Unmarshall({ entries[i].begin(), entries[i].end() }, values[i]);
        }
        return true;
    }

    API_EXPORT bool DelMeta(const std::string &key, bool isLocal = false);
    API_EXPORT bool DelMeta(const std::vector<std::string> &keys, bool isLocal = false);
    API_EXPORT bool Subscribe(std::shared_ptr<Filter> filter, Observer observer);
    API_EXPORT bool Subscribe(std::string prefix, Observer observer, bool isLocal = false);
    API_EXPORT bool Unsubscribe(std::string filter);
    API_EXPORT bool Sync(const std::vector<std::string> &devices, OnComplete complete, bool wait = false);

private:
    MetaDataManager();
    ~MetaDataManager();

    API_EXPORT bool GetEntries(const std::string &prefix, std::vector<Bytes> &entries, bool isLocal);

    void DelCacheMeta(const std::string &key, bool isLocal)
    {
        if (!isLocal) {
            return;
        }
        localdata_.Delete(key);
    }

    bool LoadCacheMeta(const std::string &key, Serializable &value, bool isLocal)
    {
        if (!isLocal) {
            return false;
        }
        std::string data;
        if (!localdata_.Get(key, data)) {
            return false;
        }
        Serializable::Unmarshall(data, value);
        return true;
    }

    void SaveCacheMeta(const std::string &key, const std::string &data, bool isLocal)
    {
        if (!isLocal) {
            return;
        }
        localdata_.Set(key, data);
    }
    
    void StopSA();

    bool inited_ = false;
    std::mutex mutex_;
    std::shared_ptr<MetaStore> metaStore_;
    ConcurrentMap<std::string, std::shared_ptr<MetaObserver>> metaObservers_;
    Backup backup_;
    Syncer syncer_;
    CloudSyncer cloudSyncer_;
    std::string storeId_;
    LRUBucket<std::string, std::string> localdata_ {64};
};
} // namespace OHOS::DistributedData
#endif // OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_METADATA_META_DATA_MANAGER_H
