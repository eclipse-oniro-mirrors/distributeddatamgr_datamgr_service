/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICE_KVDB_SERVICE_IMPL_H
#define OHOS_DISTRIBUTED_DATA_SERVICE_KVDB_SERVICE_IMPL_H
#include <set>
#include <vector>

#include "concurrent_map.h"
#include "crypto/crypto_manager.h"
#include "device_matrix.h"
#include "kv_store_delegate_manager.h"
#include "kv_store_nb_delegate.h"
#include "kvdb_notifier_proxy.h"
#include "kvdb_service_stub.h"
#include "kvdb_watcher.h"
#include "kvstore_sync_manager.h"
#include "metadata/meta_data_manager.h"
#include "metadata/store_meta_data.h"
#include "metadata/store_meta_data_local.h"
#include "metadata/strategy_meta_data.h"
#include "store/auto_cache.h"
#include "store/general_value.h"
#include "utils/ref_count.h"
namespace OHOS::DistributedKv {
class KVDBServiceImpl final : public KVDBServiceStub {
public:
    using DBLaunchParam = DistributedDB::AutoLaunchParam;
    using Handler = std::function<void(int, std::map<std::string, std::vector<std::string>> &)>;
    using RefCount = DistributedData::RefCount;
    using StoreMetaData = OHOS::DistributedData::StoreMetaData;
    KVDBServiceImpl();
    virtual ~KVDBServiceImpl();
    Status GetStoreIds(const AppId &appId, int32_t subUser, std::vector<StoreId> &storeIds) override;
    Status BeforeCreate(const AppId &appId, const StoreId &storeId, const Options &options) override;
    Status AfterCreate(const AppId &appId, const StoreId &storeId, const Options &options,
        const std::vector<uint8_t> &password) override;
    Status Delete(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status Close(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status CloudSync(const AppId &appId, const StoreId &storeId, const SyncInfo &syncInfo) override;
    Status Sync(const AppId &appId, const StoreId &storeId, int32_t subUser, SyncInfo &syncInfo) override;
    Status RegServiceNotifier(const AppId &appId, sptr<IKVDBNotifier> notifier) override;
    Status UnregServiceNotifier(const AppId &appId) override;
    Status SetSyncParam(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const KvSyncParam &syncParam) override;
    Status GetSyncParam(const AppId &appId, const StoreId &storeId, int32_t subUser, KvSyncParam &syncParam) override;
    Status EnableCapability(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status DisableCapability(const AppId &appId, const StoreId &storeId, int32_t subUser) override;
    Status SetCapability(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const std::vector<std::string> &local, const std::vector<std::string> &remote) override;
    Status AddSubscribeInfo(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const SyncInfo &syncInfo) override;
    Status RmvSubscribeInfo(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const SyncInfo &syncInfo) override;
    Status Subscribe(const AppId &appId, const StoreId &storeId, int32_t subUser,
        sptr<IKvStoreObserver> observer) override;
    Status Unsubscribe(const AppId &appId, const StoreId &storeId, int32_t subUser,
        sptr<IKvStoreObserver> observer) override;
    Status GetBackupPassword(const AppId &appId, const StoreId &storeId, int32_t subUser,
        std::vector<std::vector<uint8_t>> &passwords, int32_t passwordType) override;
    Status NotifyDataChange(const AppId &appId, const StoreId &storeId, uint64_t delay) override;
    Status PutSwitch(const AppId &appId, const SwitchData &data) override;
    Status GetSwitch(const AppId &appId, const std::string &networkId, SwitchData &data) override;
    Status SubscribeSwitchData(const AppId &appId) override;
    Status UnsubscribeSwitchData(const AppId &appId) override;
    Status SetConfig(const AppId &appId, const StoreId &storeId, const StoreConfig &storeConfig) override;
    int32_t OnBind(const BindInfo &bindInfo) override;
    int32_t OnInitialize() override;
    int32_t OnAppExit(pid_t uid, pid_t pid, uint32_t tokenId, const std::string &appId) override;
    int32_t ResolveAutoLaunch(const std::string &identifier, DBLaunchParam &param) override;
    int32_t OnUserChange(uint32_t code, const std::string &user, const std::string &account) override;
    Status RemoveDeviceData(const AppId &appId, const StoreId &storeId, int32_t subUser,
        const std::string &device) override;

private:
    using StrategyMeta = OHOS::DistributedData::StrategyMeta;
    using StoreMetaDataLocal = OHOS::DistributedData::StoreMetaDataLocal;
    using ChangeType = OHOS::DistributedData::DeviceMatrix::ChangeType;
    using DBStore = DistributedDB::KvStoreNbDelegate;
    using DBManager = DistributedDB::KvStoreDelegateManager;
    using SyncEnd = KvStoreSyncManager::SyncEnd;
    using DBResult = std::map<std::string, DistributedDB::DBStatus>;
    using DBStatus = DistributedDB::DBStatus;
    using DBMode = DistributedDB::SyncMode;
    using Action = OHOS::DistributedData::MetaDataManager::Action;
    using GeneralError = DistributedData::GeneralError;
    using CryptoManager = DistributedData::CryptoManager;
    enum SyncAction {
        ACTION_SYNC,
        ACTION_SUBSCRIBE,
        ACTION_UNSUBSCRIBE,
    };
    struct SyncAgent {
        pid_t pid_ = 0;
        int32_t switchesObserverCount_ = 0;
        bool staticsChanged_ = false;
        bool dynamicChanged_ = false;
        AppId appId_;
        sptr<IKVDBNotifier> notifier_;
        std::map<std::string, uint32_t> delayTimes_;
        std::map<std::string, std::set<std::shared_ptr<KVDBWatcher>>> watchers_;
        void ReInit(pid_t pid, const AppId &appId);
    };
    class Factory {
    public:
        Factory();
        ~Factory();

    private:
        std::shared_ptr<KVDBServiceImpl> product_;
    };

    void Init();
    void AddOptions(const Options &options, StoreMetaData &metaData);
    StoreMetaData GetStoreMetaData(const AppId &appId, const StoreId &storeId, int32_t subUser = 0);
    StoreMetaData LoadStoreMetaData(const AppId &appId, const StoreId &storeId, int32_t subUser = 0);
    StoreMetaData GetDistributedDataMeta(const std::string &deviceId);
    StrategyMeta GetStrategyMeta(const AppId &appId, const StoreId &storeId, int32_t subUser = 0);
    int32_t GetInstIndex(uint32_t tokenId, const AppId &appId);
    bool IsNeedMetaSync(const StoreMetaData &meta, const std::vector<std::string> &uuids);
    Status DoCloudSync(const StoreMetaData &meta, const SyncInfo &syncInfo);
    void DoCloudSync(bool statics, bool dynamic);
    Status DoSync(const StoreMetaData &meta, const SyncInfo &info, const SyncEnd &complete, int32_t type);
    Status DoSyncInOrder(const StoreMetaData &meta, const SyncInfo &info, const SyncEnd &complete, int32_t type);
    Status DoSyncBegin(const std::vector<std::string> &devices, const StoreMetaData &meta, const SyncInfo &info,
        const SyncEnd &complete, int32_t type);
    Status DoComplete(const StoreMetaData &meta, const SyncInfo &info, RefCount refCount, const DBResult &dbResult);
    uint32_t GetSyncDelayTime(uint32_t delay, const StoreId &storeId, const std::string &subUser = "");
    Status ConvertDbStatus(DBStatus status) const;
    Status ConvertGeneralErr(GeneralError error) const;
    DBMode ConvertDBMode(SyncMode syncMode) const;
    ChangeType ConvertType(SyncMode syncMode) const;
    SwitchState ConvertAction(Action action) const;
    SyncMode GetSyncMode(bool local, bool remote) const;
    std::vector<std::string> ConvertDevices(const std::vector<std::string> &deviceIds) const;
    DistributedData::GeneralStore::SyncMode ConvertGeneralSyncMode(SyncMode syncMode, SyncAction syncAction) const;
    DBResult HandleGenBriefDetails(const DistributedData::GenDetails &details);
    ProgressDetail HandleGenDetails(const DistributedData::GenDetails &details);
    void OnAsyncComplete(uint32_t tokenId, uint64_t seqNum, ProgressDetail &&detail);
    DistributedData::AutoCache::Watchers GetWatchers(uint32_t tokenId, const std::string &storeId,
        const std::string &userId);
    using SyncResult = std::pair<std::vector<std::string>, std::map<std::string, DBStatus>>;
    SyncResult ProcessResult(const std::map<std::string, int32_t> &results);
    void SaveLocalMetaData(const Options &options, const StoreMetaData &metaData);
    void RegisterKvServiceInfo();
    void RegisterHandler();
    void DumpKvServiceInfo(int fd, std::map<std::string, std::vector<std::string>> &params);
    void TryToSync(const StoreMetaData &metaData, bool force = false);
    bool IsRemoteChange(const StoreMetaData &metaData, const std::string &device);
    bool IsOHOSType(const std::vector<std::string> &ids);
    Status ConvertDbStatusNative(DBStatus status);
    bool CompareTripleIdentifier(const std::string &accountId, const std::string &identifier,
        const StoreMetaData &storeMeta);
    std::string GenerateKey(const std::string &userId, const std::string &storeId) const;
    std::vector<uint8_t> LoadSecretKey(const StoreMetaData &metaData, CryptoManager::SecretKeyType secretKeyType);
    void SaveSecretKeyMeta(const StoreMetaData &metaData, const std::vector<uint8_t> &password);
    static Factory factory_;
    ConcurrentMap<uint32_t, SyncAgent> syncAgents_;
    std::shared_ptr<ExecutorPool> executors_;
    std::atomic_uint64_t syncId_ = 0;
    static constexpr int32_t OH_OS_TYPE = 10;
};
} // namespace OHOS::DistributedKv
#endif // OHOS_DISTRIBUTED_DATA_SERVICE_KVDB_SERVICE_IMPL_H