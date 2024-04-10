/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "SyncManager"
#include "sync_manager.h"

#include "account/account_delegate.h"
#include "cloud/cloud_server.h"
#include "cloud/schema_meta.h"
#include "cloud/sync_event.h"
#include "device_manager_adapter.h"
#include "eventcenter/event_center.h"
#include "log_print.h"
#include "metadata/meta_data_manager.h"
#include "sync_strategies/network_sync_strategy.h"
#include "store/auto_cache.h"
#include "user_delegate.h"
#include "utils/anonymous.h"
namespace OHOS::CloudData {
using namespace DistributedData;
using namespace DistributedKv;
using Account = OHOS::DistributedKv::AccountDelegate;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;
using Defer = EventCenter::Defer;
std::atomic<uint32_t> SyncManager::genId_ = 0;
SyncManager::SyncInfo::SyncInfo(int32_t user, const std::string &bundleName, const Store &store, const Tables &tables)
    : user_(user), bundleName_(bundleName)
{
    if (!store.empty()) {
        tables_[store] = tables;
    }
    syncId_ = SyncManager::GenerateId(user);
}

SyncManager::SyncInfo::SyncInfo(int32_t user, const std::string &bundleName, const Stores &stores)
    : user_(user), bundleName_(bundleName)
{
    for (auto &store : stores) {
        tables_[store] = {};
    }
    syncId_ = SyncManager::GenerateId(user);
}

SyncManager::SyncInfo::SyncInfo(int32_t user, const std::string &bundleName, const MutliStoreTables &tables)
    : user_(user), bundleName_(bundleName), tables_(tables)
{
    tables_ = tables;
    syncId_ = SyncManager::GenerateId(user);
}

void SyncManager::SyncInfo::SetMode(int32_t mode)
{
    mode_ = mode;
}

void SyncManager::SyncInfo::SetWait(int32_t wait)
{
    wait_ = wait;
}

void SyncManager::SyncInfo::SetAsyncDetail(GenAsync asyncDetail)
{
    async_ = std::move(asyncDetail);
}

void SyncManager::SyncInfo::SetQuery(std::shared_ptr<GenQuery> query)
{
    query_ = query;
}

void SyncManager::SyncInfo::SetError(int32_t code) const
{
    if (async_) {
        GenDetails details;
        auto &detail = details[id_];
        detail.progress = SYNC_FINISH;
        detail.code = code;
        async_(std::move(details));
    }
}

std::shared_ptr<GenQuery> SyncManager::SyncInfo::GenerateQuery(const std::string &store, const Tables &tables)
{
    if (query_ != nullptr) {
        return query_;
    }
    class SyncQuery final : public GenQuery {
    public:
        explicit SyncQuery(const std::vector<std::string> &tables) : tables_(tables) {}

        bool IsEqual(uint64_t tid) override
        {
            return false;
        }

        std::vector<std::string> GetTables() override
        {
            return tables_;
        }

    private:
        std::vector<std::string> tables_;
    };
    auto it = tables_.find(store);
    return std::make_shared<SyncQuery>(it == tables_.end() || it->second.empty() ? tables : it->second);
}

bool SyncManager::SyncInfo::Contains(const std::string &storeName)
{
    return tables_.empty() || tables_.find(storeName) != tables_.end();
}

SyncManager::SyncManager()
{
    EventCenter::GetInstance().Subscribe(CloudEvent::LOCAL_CHANGE, GetClientChangeHandler());
    syncStrategy_ = std::make_shared<NetworkSyncStrategy>();
}

SyncManager::~SyncManager()
{
    if (executor_ != nullptr) {
        actives_.ForEachCopies([this](auto &syncId, auto &taskId) {
            executor_->Remove(taskId);
            return false;
        });
        executor_ = nullptr;
    }
}

int32_t SyncManager::Bind(std::shared_ptr<ExecutorPool> executor)
{
    executor_ = executor;
    return E_OK;
}

int32_t SyncManager::DoCloudSync(SyncInfo syncInfo)
{
    if (executor_ == nullptr) {
        return E_NOT_INIT;
    }
    auto syncId = GenerateId(syncInfo.user_);
    auto ref = GenSyncRef(syncId);
    actives_.Compute(syncId, [this, &ref, &syncInfo](const uint64_t &key, TaskId &taskId) mutable {
        taskId = executor_->Execute(GetSyncTask(0, true, ref, std::move(syncInfo)));
        return true;
    });
    return E_OK;
}

int32_t SyncManager::StopCloudSync(int32_t user)
{
    if (executor_ == nullptr) {
        return E_NOT_INIT;
    }
    actives_.ForEachCopies([this, user](auto &syncId, auto &taskId) {
        if (Compare(syncId, user) == 0) {
            executor_->Remove(taskId);
        }
        return false;
    });
    return E_OK;
}

bool SyncManager::IsValid(SyncInfo &info, CloudInfo &cloud)
{
    if (!MetaDataManager::GetInstance().LoadMeta(cloud.GetKey(), cloud, true) ||
        (info.id_ != SyncInfo::DEFAULT_ID && cloud.id != info.id_)) {
        info.SetError(E_CLOUD_DISABLED);
        ZLOGE("cloudInfo invalid:%{public}d, <syncId:%{public}s, metaId:%{public}s>", cloud.IsValid(),
            Anonymous::Change(info.id_).c_str(), Anonymous::Change(cloud.id).c_str());
        return false;
    }
    if (!cloud.enableCloud || (!info.bundleName_.empty() && !cloud.IsOn(info.bundleName_))) {
        info.SetError(E_CLOUD_DISABLED);
        ZLOGD("enable:%{public}d, bundleName:%{public}s", cloud.enableCloud, info.bundleName_.c_str());
        return false;
    }
    if (!DmAdapter::GetInstance().IsNetworkAvailable()) {
        info.SetError(E_NETWORK_ERROR);
        ZLOGD("network unavailable");
        return false;
    }
    if (!Account::GetInstance()->IsVerified(info.user_)) {
        info.SetError(E_USER_UNLOCK);
        ZLOGD("user unverified");
        return false;
    }
    return true;
}

ExecutorPool::Task SyncManager::GetSyncTask(int32_t times, bool retry, RefCount ref, SyncInfo &&syncInfo)
{
    times++;
    return [this, times, retry, keep = std::move(ref), info = std::move(syncInfo)]() mutable {
        activeInfos_.Erase(info.syncId_);
        CloudInfo cloud;
        cloud.user = info.user_;
        if (!IsValid(info, cloud)) {
            return;
        }
        std::vector<SchemaMeta> schemas;
        auto key = cloud.GetSchemaPrefix(info.bundleName_);
        auto retryer = GetRetryer(times, info);
        if (!MetaDataManager::GetInstance().LoadMeta(key, schemas, true) || schemas.empty()) {
            UpdateSchema(info);
            retryer(RETRY_INTERVAL, E_RETRY_TIMEOUT);
            return;
        }
        Defer defer(GetSyncHandler(std::move(retryer)), CloudEvent::CLOUD_SYNC);
        for (auto &schema : schemas) {
            if (!cloud.IsOn(schema.bundleName)) {
                continue;
            }
            for (const auto &database : schema.databases) {
                if (!info.Contains(database.name)) {
                    continue;
                }
                StoreInfo storeInfo = { 0, schema.bundleName, database.name, cloud.apps[schema.bundleName].instanceId,
                    cloud.user };
                auto status = syncStrategy_->CheckSyncAction(storeInfo);
                if (status != SUCCESS) {
                    ZLOGW("Verification strategy failed, status:%{public}d. %{public}d:%{public}s:%{public}s", status,
                        storeInfo.user, storeInfo.bundleName.c_str(), Anonymous::Change(storeInfo.storeName).c_str());
                    info.SetError(status);
                    continue;
                }
                auto query = info.GenerateQuery(database.name, database.GetTableNames());
                auto evt = std::make_unique<SyncEvent>(std::move(storeInfo),
                    SyncEvent::EventInfo { info.mode_, info.wait_, retry, std::move(query), info.async_ });
                EventCenter::GetInstance().PostEvent(std::move(evt));
            }
        }
    };
}

std::function<void(const Event &)> SyncManager::GetSyncHandler(Retryer retryer)
{
    return [retryer](const Event &event) {
        auto &evt = static_cast<const SyncEvent &>(event);
        auto &storeInfo = evt.GetStoreInfo();
        StoreMetaData meta;
        meta.storeId = storeInfo.storeName;
        meta.bundleName = storeInfo.bundleName;
        meta.user = std::to_string(storeInfo.user);
        meta.instanceId = storeInfo.instanceId;
        meta.deviceId = DmAdapter::GetInstance().GetLocalDevice().uuid;
        if (!MetaDataManager::GetInstance().LoadMeta(meta.GetKey(), meta, true)) {
            ZLOGE("failed, no store meta bundleName:%{public}s, storeId:%{public}s", meta.bundleName.c_str(),
                meta.GetStoreAlias().c_str());
            return;
        }
        auto store = GetStore(meta, storeInfo.user);
        if (store == nullptr) {
            ZLOGE("store null, storeId:%{public}s", meta.GetStoreAlias().c_str());
            return;
        }

        ZLOGD("database:<%{public}d:%{public}s:%{public}s> sync start", storeInfo.user, storeInfo.bundleName.c_str(),
            meta.GetStoreAlias().c_str());
        auto status = store->Sync({ SyncInfo::DEFAULT_ID }, evt.GetMode(), *(evt.GetQuery()), evt.AutoRetry()
            ? [retryer](const GenDetails &details) {
                if (details.empty()) {
                    ZLOGE("retry, details empty");
                    return;
                }
                int32_t code = details.begin()->second.code;
                retryer(code == E_LOCKED_BY_OTHERS ? LOCKED_INTERVAL : RETRY_INTERVAL, code);
            }
            : evt.GetAsyncDetail(), evt.GetWait());
        GenAsync async = evt.GetAsyncDetail();
        if (status != E_OK && async) {
            GenDetails details;
            auto &detail = details[SyncInfo::DEFAULT_ID];
            detail.progress = SYNC_FINISH;
            detail.code = status;
            async(std::move(details));
        }
    };
}

std::function<void(const Event &)> SyncManager::GetClientChangeHandler()
{
    return [this](const Event &event) {
        auto &evt = static_cast<const SyncEvent &>(event);
        auto store = evt.GetStoreInfo();
        SyncInfo syncInfo(store.user, store.bundleName, store.storeName);
        syncInfo.SetMode(evt.GetMode());
        syncInfo.SetWait(evt.GetWait());
        syncInfo.SetAsyncDetail(evt.GetAsyncDetail());
        syncInfo.SetQuery(evt.GetQuery());
        auto times = evt.AutoRetry() ? RETRY_TIMES - CLIENT_RETRY_TIMES : RETRY_TIMES;
        auto task = GetSyncTask(times, evt.AutoRetry(), RefCount(), std::move(syncInfo));
        task();
    };
}

SyncManager::Retryer SyncManager::GetRetryer(int32_t times, const SyncInfo &syncInfo)
{
    if (times >= RETRY_TIMES) {
        return  [info = SyncInfo(syncInfo)](Duration, int32_t code) mutable {
            if (code == E_OK) {
                return true;
            }
            info.SetError(code);
            return true;
        };
    }
    return [this, times, info = SyncInfo(syncInfo)](Duration interval, int32_t code) mutable {
        if (code == E_OK) {
            return true;
        }

        activeInfos_.ComputeIfAbsent(info.syncId_, [this, times, interval, &info](uint64_t key) mutable {
            auto syncId = GenerateId(info.user_);
            auto ref = GenSyncRef(syncId);
            actives_.Compute(syncId, [this, times, interval, &ref, &info](const uint64_t &key, TaskId &value) mutable {
                value = executor_->Schedule(interval, GetSyncTask(times, true, ref, std::move(info)));
                return true;
            });
            return syncId;
        });
        return true;
    };
}

uint64_t SyncManager::GenerateId(int32_t user)
{
    uint64_t syncId = static_cast<uint64_t>(user) & 0xFFFFFFFF;
    return (syncId << MV_BIT) | (++genId_);
}

RefCount SyncManager::GenSyncRef(uint64_t syncId)
{
    return RefCount([syncId, this]() {
        actives_.Erase(syncId);
    });
}

int32_t SyncManager::Compare(uint64_t syncId, int32_t user)
{
    uint64_t inner = static_cast<uint64_t>(user) & 0xFFFFFFFF;
    return (syncId & USER_MARK) == (inner << MV_BIT);
}

void SyncManager::UpdateSchema(const SyncManager::SyncInfo &syncInfo)
{
    StoreInfo storeInfo;
    storeInfo.user = syncInfo.user_;
    storeInfo.bundleName = syncInfo.bundleName_;
    EventCenter::GetInstance().PostEvent(std::make_unique<CloudEvent>(CloudEvent::GET_SCHEMA, storeInfo));
}

AutoCache::Store SyncManager::GetStore(const StoreMetaData &meta, int32_t user, bool mustBind)
{
    if (!Account::GetInstance()->IsVerified(user)) {
        ZLOGW("user:%{public}d is locked!", user);
        return nullptr;
    }
    auto instance = CloudServer::GetInstance();
    if (instance == nullptr) {
        ZLOGD("not support cloud sync");
        return nullptr;
    }

    auto store = AutoCache::GetInstance().GetStore(meta, {});
    if (store == nullptr) {
        ZLOGE("store null, storeId:%{public}s", meta.GetStoreAlias().c_str());
        return nullptr;
    }

    if (!store->IsBound()) {
        std::set<std::string> activeUsers = UserDelegate::GetInstance().GetLocalUsers();
        std::map<std::string, std::pair<Database, GeneralStore::BindInfo>> cloudDBs = {};
        for (auto &activeUser : activeUsers) {
            CloudInfo info;
            info.user = std::stoi(activeUser);
            SchemaMeta schemaMeta;
            std::string schemaKey = info.GetSchemaKey(meta.bundleName, meta.instanceId);
            if (!MetaDataManager::GetInstance().LoadMeta(std::move(schemaKey), schemaMeta, true)) {
                ZLOGE("failed, no schema bundleName:%{public}s, storeId:%{public}s", meta.bundleName.c_str(),
                    meta.GetStoreAlias().c_str());
                return nullptr;
            }
            auto dbMeta = schemaMeta.GetDataBase(meta.storeId);
            auto cloudDB = instance->ConnectCloudDB(meta.tokenId, dbMeta);
            auto assetLoader = instance->ConnectAssetLoader(meta.tokenId, dbMeta);
            if (mustBind && (cloudDB == nullptr || assetLoader == nullptr)) {
                ZLOGE("failed, no cloud DB <0x%{public}x %{public}s<->%{public}s>", meta.tokenId,
                    Anonymous::Change(dbMeta.name).c_str(), Anonymous::Change(dbMeta.alias).c_str());
                return nullptr;
            }
            if (cloudDB != nullptr || assetLoader != nullptr) {
                GeneralStore::BindInfo bindInfo(std::move(cloudDB), std::move(assetLoader));
                cloudDBs[activeUser] = std::make_pair(dbMeta, bindInfo);
            }
        }
        store->Bind(cloudDBs);
    }
    return store;
}
} // namespace OHOS::CloudData