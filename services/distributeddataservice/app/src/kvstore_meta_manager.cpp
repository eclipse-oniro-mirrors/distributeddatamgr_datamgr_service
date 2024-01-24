/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define LOG_TAG "KvStoreMetaManager"

#include "kvstore_meta_manager.h"

#include <ipc_skeleton.h>
#include <thread>
#include <unistd.h>

#include "account_delegate.h"
#include "bootstrap.h"
#include "communication_provider.h"
#include "crypto_manager.h"
#include "device_manager_adapter.h"
#include "device_matrix.h"
#include "directory/directory_manager.h"
#include "eventcenter/event_center.h"
#include "kvstore_data_service.h"
#include "log_print.h"
#include "matrix_event.h"
#include "metadata/meta_data_manager.h"
#include "utils/anonymous.h"
#include "utils/block_integer.h"
#include "utils/crypto.h"
#include "utils/ref_count.h"

namespace OHOS {
namespace DistributedKv {
using Commu = AppDistributedKv::CommunicationProvider;
using DmAdapter = DistributedData::DeviceManagerAdapter;
using namespace std::chrono;
using namespace OHOS::DistributedData;
using namespace DistributedDB;
using namespace OHOS::AppDistributedKv;

KvStoreMetaManager::MetaDeviceChangeListenerImpl KvStoreMetaManager::listener_;

KvStoreMetaManager::KvStoreMetaManager()
    : metaDelegate_(nullptr), metaDBDirectory_(DirectoryManager::GetInstance().GetMetaStorePath()),
      label_(Bootstrap::GetInstance().GetProcessLabel()),
      delegateManager_(Bootstrap::GetInstance().GetProcessLabel(), "default")
{
    ZLOGI("begin.");
}

KvStoreMetaManager::~KvStoreMetaManager()
{
    if (delaySyncTaskId_ != ExecutorPool::INVALID_TASK_ID) {
        executors_->Remove(delaySyncTaskId_);
        delaySyncTaskId_ = ExecutorPool::INVALID_TASK_ID;
    }
}

KvStoreMetaManager &KvStoreMetaManager::GetInstance()
{
    static KvStoreMetaManager instance;
    return instance;
}

void KvStoreMetaManager::SubscribeMeta(const std::string &keyPrefix, const ChangeObserver &observer)
{
    metaObserver_.handlerMap_[keyPrefix] = observer;
}

void KvStoreMetaManager::InitMetaListener()
{
    InitMetaData();
    auto status = DmAdapter::GetInstance().StartWatchDeviceChange(&listener_, { "metaMgr" });
    if (status != AppDistributedKv::Status::SUCCESS) {
        ZLOGW("register failed.");
        return;
    }
    ZLOGI("register meta device change success.");
    SubscribeMetaKvStore();
    SyncMeta();
    InitBroadcast();
    InitDeviceOnline();
}

void KvStoreMetaManager::InitBroadcast()
{
    auto pipe = Bootstrap::GetInstance().GetProcessLabel() + "-" + "default";
    auto result = Commu::GetInstance().ListenBroadcastMsg({ pipe },
        [](const std::string &device, uint16_t mask) { DeviceMatrix::GetInstance().OnBroadcast(device, mask); });

    EventCenter::GetInstance().Subscribe(DeviceMatrix::MATRIX_BROADCAST, [pipe](const Event &event) {
        auto &matrixEvent = static_cast<const MatrixEvent &>(event);
        Commu::GetInstance().Broadcast({ pipe }, matrixEvent.GetMask());
    });

    ZLOGI("observer matrix broadcast %{public}d.", result);
}

void KvStoreMetaManager::InitDeviceOnline()
{
    ZLOGI("observer matrix online event.");
    using DBStatuses = std::map<std::string, DBStatus>;
    EventCenter::GetInstance().Subscribe(DeviceMatrix::MATRIX_ONLINE, [this](const Event &event) {
        auto &matrixEvent = static_cast<const MatrixEvent &>(event);
        auto mask = matrixEvent.GetMask();
        auto deviceId = matrixEvent.GetDeviceId();
        auto store = GetMetaKvStore();
        auto onComplete = [deviceId, mask, refCount = matrixEvent.StealRefCount()](const DBStatuses &statuses) mutable {
            auto finEvent = std::make_unique<MatrixEvent>(DeviceMatrix::MATRIX_META_FINISHED, deviceId, mask);
            finEvent->SetRefCount(std::move(refCount));
            auto it = statuses.find(deviceId);
            if (it != statuses.end() && it->second == DBStatus::OK) {
                DeviceMatrix::GetInstance().OnExchanged(deviceId, DeviceMatrix::META_STORE_MASK);
            }
            ZLOGI("matrix 0x%{public}08x device:%{public}s status:%{public}d online",
                mask, Anonymous::Change(deviceId).c_str(), it == statuses.end() ? DBStatus::OK : it->second);
            EventCenter::GetInstance().PostEvent(std::move(finEvent));
        };
        if (((mask & DeviceMatrix::META_STORE_MASK) != 0) && store != nullptr) {
            auto status = store->Sync({ deviceId }, DistributedDB::SyncMode::SYNC_MODE_PUSH_PULL, onComplete);
            if (status == OK) {
                return;
            }
            ZLOGW("meta online sync error 0x%{public}08x device:%{public}s %{public}d", mask,
                Anonymous::Change(deviceId).c_str(), status);
        }
        onComplete({ });
    });
}

void KvStoreMetaManager::InitMetaData()
{
    ZLOGI("start.");
    auto metaDelegate = GetMetaKvStore();
    if (metaDelegate == nullptr) {
        ZLOGI("get meta failed.");
        return;
    }
    auto uid = getuid();
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    const std::string accountId = AccountDelegate::GetInstance()->GetCurrentAccountId();
    auto userId = AccountDelegate::GetInstance()->GetUserByToken(tokenId);
    StoreMetaData data;
    data.appId = label_;
    data.appType = "default";
    data.bundleName = label_;
    data.dataDir = metaDBDirectory_;
    data.user = std::to_string(userId);
    data.deviceId = DmAdapter::GetInstance().GetLocalDevice().uuid;
    data.isAutoSync = false;
    data.isBackup = false;
    data.isEncrypt = false;
    data.storeType = KvStoreType::SINGLE_VERSION;
    data.schema = "";
    data.storeId = Bootstrap::GetInstance().GetMetaDBName();
    data.account = accountId;
    data.uid = static_cast<int32_t>(uid);
    data.version = META_STORE_VERSION;
    data.securityLevel = SecurityLevel::S1;
    data.area = EL1;
    data.tokenId = tokenId;
    if (!(MetaDataManager::GetInstance().SaveMeta(data.GetKey(), data) &&
        MetaDataManager::GetInstance().SaveMeta(data.GetKey(), data, true))) {
        ZLOGE("save meta fail");
    }
    ZLOGI("end.");
}

void KvStoreMetaManager::InitMetaParameter()
{
    ZLOGI("start.");
    executors_->Execute(GetTask(0));
    DistributedDB::KvStoreConfig kvStoreConfig{ metaDBDirectory_ };
    delegateManager_.SetKvStoreConfig(kvStoreConfig);
}

ExecutorPool::Task KvStoreMetaManager::GetTask(uint32_t retry)
{
    return [this, retry] {
        auto status = CryptoManager::GetInstance().CheckRootKey();
        if (status == CryptoManager::ErrCode::SUCCESS) {
            ZLOGI("root key exist.");
            return;
        }
        if (status == CryptoManager::ErrCode::NOT_EXIST &&
            CryptoManager::GetInstance().GenerateRootKey() == CryptoManager::ErrCode::SUCCESS) {
            ZLOGI("GenerateRootKey success.");
            return;
        }
        ZLOGW("GenerateRootKey failed, retry times:%{public}d.", static_cast<int>(retry));
        if (retry + 1 > RETRY_MAX_TIMES) {
            ZLOGE("fail to register subscriber!");
            return;
        }
        executors_->Schedule(std::chrono::seconds(RETRY_INTERVAL), GetTask(retry + 1));
    };
}

KvStoreMetaManager::NbDelegate KvStoreMetaManager::GetMetaKvStore()
{
    if (metaDelegate_ != nullptr) {
        return metaDelegate_;
    }

    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (metaDelegate_ == nullptr) {
        metaDelegate_ = CreateMetaKvStore();
    }
    ConfigMetaDataManager();
    return metaDelegate_;
}

KvStoreMetaManager::NbDelegate KvStoreMetaManager::CreateMetaKvStore()
{
    DistributedDB::DBStatus dbStatusTmp = DistributedDB::DBStatus::NOT_SUPPORT;
    DistributedDB::KvStoreNbDelegate::Option option;
    option.createIfNecessary = true;
    option.isMemoryDb = false;
    option.createDirByStoreIdOnly = true;
    option.isEncryptedDb = false;
    option.isNeedRmCorruptedDb = true;
    option.isNeedCompressOnSync = true;
    option.compressionRate = COMPRESS_RATE;
    option.secOption = { DistributedDB::S1, DistributedDB::ECE };
    DistributedDB::KvStoreNbDelegate *delegate = nullptr;
    delegateManager_.GetKvStore(Bootstrap::GetInstance().GetMetaDBName(), option,
        [&delegate, &dbStatusTmp](DistributedDB::DBStatus dbStatus, DistributedDB::KvStoreNbDelegate *nbDelegate) {
            delegate = nbDelegate;
            dbStatusTmp = dbStatus;
        });

    if (dbStatusTmp != DistributedDB::DBStatus::OK || delegate == nullptr) {
        ZLOGE("GetKvStore return error status: %{public}d or delegate is nullptr", static_cast<int>(dbStatusTmp));
        return nullptr;
    }
    delegate->SetRemotePushFinishedNotify([](const RemotePushNotifyInfo &info) {
        DeviceMatrix::GetInstance().OnExchanged(info.deviceId, DeviceMatrix::META_STORE_MASK);
    });
    bool param = true;
    auto data = static_cast<DistributedDB::PragmaData>(&param);
    delegate->Pragma(DistributedDB::SET_SYNC_RETRY, data);
    auto release = [this](DistributedDB::KvStoreNbDelegate *delegate) {
        ZLOGI("release meta data  kv store");
        if (delegate == nullptr) {
            return;
        }

        auto result = delegateManager_.CloseKvStore(delegate);
        if (result != DistributedDB::DBStatus::OK) {
            ZLOGE("CloseMetaKvStore return error status: %{public}d", static_cast<int>(result));
        }
    };
    return NbDelegate(delegate, release);
}

void KvStoreMetaManager::ConfigMetaDataManager()
{
    auto fullName = GetBackupPath();
    auto backup = [fullName](const auto &store) -> int32_t {
        DistributedDB::CipherPassword password;
        return store->Export(fullName, password);
    };
    auto syncer = [this](const auto &store, int32_t status) {
        DeviceMatrix::GetInstance().OnChanged(DeviceMatrix::META_STORE_MASK);
        ZLOGI("Syncer status: %{public}d", status);
        std::lock_guard<decltype(mutex_)> lock(mutex_);
        if (delaySyncTaskId_ == Executor::INVALID_TASK_ID) {
            delaySyncTaskId_ =
                executors_->Schedule(std::chrono::milliseconds(DELAY_SYNC), SyncTask(store, status));
        } else {
            delaySyncTaskId_ =
                executors_->Reset(delaySyncTaskId_, std::chrono::milliseconds(DELAY_SYNC));
        }
    };
    MetaDataManager::GetInstance().Initialize(metaDelegate_, backup, syncer);
}

std::function<void()> KvStoreMetaManager::SyncTask(const NbDelegate &store, int32_t status)
{
    return [this, store, status]() mutable {
        {
            std::lock_guard<decltype(mutex_)> lock(mutex_);
            delaySyncTaskId_ = ExecutorPool::INVALID_TASK_ID;
        }
        std::vector<std::string> devs;
        auto devices = DmAdapter::GetInstance().GetRemoteDevices();
        for (auto const &dev : devices) {
            devs.push_back(dev.uuid);
        }
        if (devs.empty()) {
            return;
        }
        status = store->Sync(devs, DistributedDB::SyncMode::SYNC_MODE_PUSH_PULL, [](auto &results) {
            for (auto &[uuid, status] : results) {
                if (status != DistributedDB::OK) {
                    continue;
                }
                DeviceMatrix::GetInstance().OnExchanged(uuid, DeviceMatrix::META_STORE_MASK);
                ZLOGI("uuid is: %{public}s, and status is: %{public}d", Anonymous::Change(uuid).c_str(), status);
            }
        });
        if (status != DistributedDB::OK) {
            ZLOGW("meta data sync error %{public}d.", status);
        }
    };
}

void KvStoreMetaManager::SyncMeta()
{
    std::vector<std::string> devs;
    auto deviceList = DmAdapter::GetInstance().GetRemoteDevices();
    for (auto const &dev : deviceList) {
        devs.push_back(dev.uuid);
    }

    if (devs.empty()) {
        ZLOGW("meta db sync fail, devices is empty.");
        return;
    }

    auto metaDelegate = GetMetaKvStore();
    if (metaDelegate == nullptr) {
        ZLOGW("meta db sync failed.");
        return;
    }
    auto onComplete = [this](const std::map<std::string, DistributedDB::DBStatus> &) {
        ZLOGD("meta db sync complete end.");
    };
    auto dbStatus = metaDelegate->Sync(devs, DistributedDB::SyncMode::SYNC_MODE_PUSH_PULL, onComplete);
    if (dbStatus != DistributedDB::OK) {
        ZLOGW("meta db sync failed, error is %{public}d.", dbStatus);
    }
}

void KvStoreMetaManager::SubscribeMetaKvStore()
{
    auto metaDelegate = GetMetaKvStore();
    if (metaDelegate == nullptr) {
        ZLOGW("register meta observer failed.");
        return;
    }

    int mode = DistributedDB::OBSERVER_CHANGES_NATIVE | DistributedDB::OBSERVER_CHANGES_FOREIGN;
    auto dbStatus = metaDelegate->RegisterObserver(DistributedDB::Key(), mode, &metaObserver_);
    if (dbStatus != DistributedDB::DBStatus::OK) {
        ZLOGW("register meta observer failed :%{public}d.", dbStatus);
    }
}

KvStoreMetaManager::KvStoreMetaObserver::~KvStoreMetaObserver()
{
    ZLOGW("meta observer destruct.");
}

void KvStoreMetaManager::KvStoreMetaObserver::OnChange(const DistributedDB::KvStoreChangedData &data)
{
    ZLOGD("on data change.");
    HandleChanges(CHANGE_FLAG::INSERT, data.GetEntriesInserted());
    HandleChanges(CHANGE_FLAG::UPDATE, data.GetEntriesUpdated());
    HandleChanges(CHANGE_FLAG::DELETE, data.GetEntriesDeleted());
}

void KvStoreMetaManager::KvStoreMetaObserver::HandleChanges(CHANGE_FLAG flag,
    const std::list<DistributedDB::Entry> &entries)
{
    for (const auto &entry : entries) {
        std::string key(entry.key.begin(), entry.key.end());
        for (const auto &item : handlerMap_) {
            ZLOGI("flag:%{public}d, key:%{public}s", flag, Anonymous::Change(key).c_str());
            if (key.find(item.first) == 0) {
                item.second(entry.key, entry.value, flag);
            }
        }
    }
}

void KvStoreMetaManager::MetaDeviceChangeListenerImpl::OnDeviceChanged(const AppDistributedKv::DeviceInfo &info,
    const AppDistributedKv::DeviceChangeType &type) const
{
    if (info.uuid == DmAdapter::CLOUD_DEVICE_UUID) {
        return;
    }
    EventCenter::Defer defer;
    switch (type) {
        case AppDistributedKv::DeviceChangeType::DEVICE_OFFLINE:
            DeviceMatrix::GetInstance().Offline(info.uuid);
            break;
        case AppDistributedKv::DeviceChangeType::DEVICE_ONLINE:
            DeviceMatrix::GetInstance().Online(info.uuid, RefCount([deviceId = info.uuid]() {
                DmAdapter::GetInstance().NotifyReadyEvent(deviceId);
            }));
            break;
        default:
            ZLOGI("flag:%{public}d", type);
            break;
    }
}

AppDistributedKv::ChangeLevelType KvStoreMetaManager::MetaDeviceChangeListenerImpl::GetChangeLevelType() const
{
    return AppDistributedKv::ChangeLevelType::LOW;
}

std::string KvStoreMetaManager::GetBackupPath() const
{
    return (DirectoryManager::GetInstance().GetMetaBackupPath() + "/" +
            Crypto::Sha256(label_ + "_" + Bootstrap::GetInstance().GetMetaDBName()));
}

void KvStoreMetaManager::BindExecutor(std::shared_ptr<ExecutorPool> executors)
{
    executors_ = executors;
}
} // namespace DistributedKv
} // namespace OHOS
