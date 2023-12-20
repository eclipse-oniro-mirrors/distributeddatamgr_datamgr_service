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
#define LOG_TAG "RuntimeStore"

#include "runtime_store.h"

#include <algorithm>
#include <vector>
#include<unistd.h>

#include "log_print.h"
#include "ipc_skeleton.h"
#include "tlv_util.h"
#include "account/account_delegate.h"
#include "metadata/store_meta_data.h"
#include "metadata/meta_data_manager.h"
#include "metadata/appid_meta_data.h"
#include "device_manager_adapter.h"
#include "bootstrap.h"
#include "directory/directory_manager.h"

namespace OHOS {
namespace UDMF {
using namespace DistributedDB;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;

RuntimeStore::RuntimeStore(const std::string &storeId) : storeId_(storeId)
{
    UpdateTime();
    ZLOGD("Construct runtimeStore: %{public}s.", storeId_.c_str());
}

RuntimeStore::~RuntimeStore()
{
    ZLOGD("Destruct runtimeStore: %{public}s.", storeId_.c_str());
}

Status RuntimeStore::Put(const UnifiedData &unifiedData)
{
    UpdateTime();
    std::vector<Entry> entries;
    std::string unifiedKey = unifiedData.GetRuntime()->key.GetUnifiedKey();
    // add runtime info
    std::vector<uint8_t> runtimeBytes;
    auto runtimeTlv = TLVObject(runtimeBytes);
    if (!TLVUtil::Writing(*unifiedData.GetRuntime(), runtimeTlv)) {
        ZLOGE("Marshall runtime info failed, dataPrefix: %{public}s.", unifiedKey.c_str());
        return E_WRITE_PARCEL_ERROR;
    }
    std::vector<uint8_t> udKeyBytes = {unifiedKey.begin(), unifiedKey.end()};
    Entry entry = {udKeyBytes, runtimeBytes};
    entries.push_back(entry);

    // add unified record
    for (const auto &record : unifiedData.GetRecords()) {
        std::vector<uint8_t> recordBytes;
        auto recordTlv = TLVObject(recordBytes);
        if (!TLVUtil::Writing(record, recordTlv)) {
            ZLOGI("Marshall unified record failed.");
            return E_WRITE_PARCEL_ERROR;
        }
        std::string recordKey = unifiedKey + "/" + record->GetUid();
        std::vector<uint8_t> keyBytes = {recordKey.begin(), recordKey.end() };
        Entry entry = { keyBytes, recordBytes };
        entries.push_back(entry);
    }
    auto status = PutEntries(entries);
    return status;
}

Status RuntimeStore::Get(const std::string &key, UnifiedData &unifiedData)
{
    UpdateTime();
    std::vector<Entry> entries;
    if (GetEntries(key, entries) != E_OK) {
        ZLOGE("GetEntries failed, dataPrefix: %{public}s.", key.c_str());
        return E_DB_ERROR;
    }
    if (entries.empty()) {
        ZLOGW("entries is empty, dataPrefix: %{public}s", key.c_str());
        return E_NOT_FOUND;
    }
    return UnmarshalEntries(key, entries, unifiedData);
}

Status RuntimeStore::GetSummary(const std::string &key, Summary &summary)
{
    UpdateTime();
    UnifiedData unifiedData;
    if (Get(key, unifiedData) != E_OK) {
        ZLOGE("Get unified data failed, dataPrefix: %{public}s", key.c_str());
        return E_DB_ERROR;
    }

    for (const auto &record : unifiedData.GetRecords()) {
        int64_t recordSize = record->GetSize();
        auto udType = UD_TYPE_MAP.at(record->GetType());
        auto it = summary.summary.find(udType);
        if (it == summary.summary.end()) {
            summary.summary[udType] = recordSize;
        } else {
            summary.summary[udType] += recordSize;
        }
        summary.totalSize += recordSize;
    }
    return E_OK;
}

Status RuntimeStore::Update(const UnifiedData &unifiedData)
{
    std::string key = unifiedData.GetRuntime()->key.key;
    if (Delete(key) != E_OK) {
        UpdateTime();
        ZLOGE("Delete unified data failed, dataPrefix: %{public}s.", key.c_str());
        return E_DB_ERROR;
    }
    if (Put(unifiedData) != E_OK) {
        ZLOGE("Update unified data failed, dataPrefix: %{public}s.", key.c_str());
        return E_DB_ERROR;
    }
    return E_OK;
}

Status RuntimeStore::Delete(const std::string &key)
{
    std::vector<Entry> entries;
    if (GetEntries(key, entries) != E_OK) {
        ZLOGE("GetEntries failed, dataPrefix: %{public}s.", key.c_str());
        return E_DB_ERROR;
    }
    if (entries.empty()) {
        ZLOGD("entries is empty.");
        return E_OK;
    }
    std::vector<Key> keys;
    for (const auto &entry : entries) {
        keys.push_back(entry.key);
    }
    return DeleteEntries(keys);
}

Status RuntimeStore::DeleteBatch(const std::vector<std::string> &unifiedKeys)
{
    UpdateTime();
    ZLOGD("called!");
    if (unifiedKeys.empty()) {
        ZLOGD("No need to delete!");
        return E_OK;
    }
    for (const std::string &unifiedKey : unifiedKeys) {
        if (Delete(unifiedKey) != E_OK) {
            ZLOGE("Delete failed, key: %{public}s.", unifiedKey.c_str());
            return E_DB_ERROR;
        }
    }
    return E_OK;
}

Status RuntimeStore::Sync(const std::vector<std::string> &devices)
{
    UpdateTime();
    if (devices.empty()) {
        ZLOGE("devices empty, no need sync.");
        return E_INVALID_PARAMETERS;
    }
    std::vector<std::string> syncDevices = DmAdapter::ToUUID(devices);
    auto onComplete = [this](const std::map<std::string, DBStatus> &) {
        ZLOGI("sync complete, %{public}s.", storeId_.c_str());
    };
    DBStatus status = kvStore_->Sync(syncDevices, SyncMode::SYNC_MODE_PULL_ONLY, onComplete);
    if (status != DBStatus::OK) {
        ZLOGE("Sync kvStore failed, status: %{public}d.", status);
        return E_DB_ERROR;
    }
    return E_OK;
}

Status RuntimeStore::Clear()
{
    UpdateTime();
    return Delete(DATA_PREFIX);
}

Status RuntimeStore::GetBatchData(const std::string &dataPrefix, std::vector<UnifiedData> &unifiedDataSet)
{
    UpdateTime();
    std::vector<Entry> entries;
    auto status = GetEntries(dataPrefix, entries);
    if (status != E_OK) {
        ZLOGE("GetEntries failed, dataPrefix: %{public}s.", dataPrefix.c_str());
        return E_DB_ERROR;
    }
    if (entries.empty()) {
        ZLOGD("entries is empty.");
        return E_OK;
    }
    std::vector<std::string> keySet;
    for (const auto &entry : entries) {
        std::string keyStr = {entry.key.begin(), entry.key.end()};
        if (std::count(keyStr.begin(), keyStr.end(), '/') == SLASH_COUNT_IN_KEY) {
            keySet.emplace_back(keyStr);
        }
    }

    for (const std::string &key : keySet) {
        UnifiedData data;
        if (UnmarshalEntries(key, entries, data) != E_OK) {
            return E_READ_PARCEL_ERROR;
        }
        unifiedDataSet.emplace_back(data);
    }
    return E_OK;
}

void RuntimeStore::Close()
{
    delegateManager_->CloseKvStore(kvStore_.get());
}

bool RuntimeStore::Init()
{
    if (!SaveMetaData()) {  // get keyinfo about create db fail.
        return false;
    }
    DistributedDB::KvStoreNbDelegate::Option option;
    option.createIfNecessary = true;
    option.isMemoryDb = false;
    option.createDirByStoreIdOnly = true;
    option.isEncryptedDb = false;
    option.isNeedRmCorruptedDb = true;
    option.syncDualTupleMode = true;
    option.secOption = {DistributedKv::SecurityLevel::S1, DistributedDB::ECE};
    DistributedDB::KvStoreNbDelegate *delegate = nullptr;
    DBStatus status = DBStatus::NOT_SUPPORT;
    delegateManager_->GetKvStore(storeId_, option,
                                 [&delegate, &status](DBStatus dbStatus, KvStoreNbDelegate *nbDelegate) {
                                     delegate = nbDelegate;
                                     status = dbStatus;
                                 });
    if (status != DBStatus::OK) {
        ZLOGE("GetKvStore fail, status: %{public}d.", static_cast<int>(status));
        return false;
    }

    auto release = [this](KvStoreNbDelegate *delegate) {
        ZLOGI("Release runtime kvStore.");
        if (delegate == nullptr) {
            return;
        }
        auto retStatus = delegateManager_->CloseKvStore(delegate);
        if (retStatus != DBStatus::OK) {
            ZLOGE("CloseKvStore fail, status: %{public}d.", static_cast<int>(retStatus));
        }
    };
    kvStore_ = std::shared_ptr<KvStoreNbDelegate>(delegate, release);
    return true;
}

bool RuntimeStore::SaveMetaData()
{
    auto localDeviceId = DmAdapter::GetInstance().GetLocalDevice().uuid;
    if (localDeviceId.empty()) {
        ZLOGE("failed to get local device id");
        return false;
    }

    uint32_t token = IPCSkeleton::GetSelfTokenID();
    const std::string userId = std::to_string(DistributedKv::AccountDelegate::GetInstance()->GetUserByToken(token));
    DistributedData::StoreMetaData saveMeta;
    saveMeta.appType = "harmony";
    saveMeta.deviceId = localDeviceId;
    saveMeta.storeId = storeId_;
    saveMeta.isAutoSync = false;
    saveMeta.isBackup = false;
    saveMeta.isEncrypt = false;
    saveMeta.bundleName = DistributedData::Bootstrap::GetInstance().GetProcessLabel();
    saveMeta.appId = DistributedData::Bootstrap::GetInstance().GetProcessLabel();
    saveMeta.user =  userId;
    saveMeta.account = DistributedKv::AccountDelegate::GetInstance()->GetCurrentAccountId();
    saveMeta.tokenId = token;
    saveMeta.securityLevel = DistributedKv::SecurityLevel::S1;
    saveMeta.area = DistributedKv::Area::EL1;
    saveMeta.uid = static_cast<int32_t>(getuid());
    saveMeta.storeType = DistributedKv::KvStoreType::SINGLE_VERSION;
    saveMeta.dataDir = DistributedData::DirectoryManager::GetInstance().GetStorePath(saveMeta);

    SetDelegateManager(saveMeta.dataDir, saveMeta.appId, userId);
    auto saved = DistributedData::MetaDataManager::GetInstance().SaveMeta(saveMeta.GetKey(), saveMeta);
    if (!saved) {
        ZLOGE("SaveMeta failed");
        return false;
    }
    DistributedData::AppIDMetaData appIdMeta;
    appIdMeta.bundleName = saveMeta.bundleName;
    appIdMeta.appId = saveMeta.appId;
    saved = DistributedData::MetaDataManager::GetInstance().SaveMeta(appIdMeta.GetKey(), appIdMeta, true);
    if (!saved) {
        ZLOGE("Save appIdMeta failed");
        return false;
    }
    return true;
}

void RuntimeStore::SetDelegateManager(const std::string &dataDir, const std::string &appId, const std::string &userId)
{
    delegateManager_ = std::make_shared<DistributedDB::KvStoreDelegateManager>(appId, userId);
    DistributedDB::KvStoreConfig kvStoreConfig { dataDir };
    delegateManager_->SetKvStoreConfig(kvStoreConfig);
}

Status RuntimeStore::GetEntries(const std::string &dataPrefix, std::vector<Entry> &entries)
{
    Query dbQuery = Query::Select();
    std::vector<uint8_t> prefix = {dataPrefix.begin(), dataPrefix.end()};
    dbQuery.PrefixKey(prefix);
    dbQuery.OrderByWriteTime(true);
    DBStatus status = kvStore_->GetEntries(dbQuery, entries);
    if (status != DBStatus::OK && status != DBStatus::NOT_FOUND) {
        ZLOGE("KvStore getEntries failed, status: %{public}d.", static_cast<int>(status));
        return E_DB_ERROR;
    }
    return E_OK;
}

Status RuntimeStore::PutEntries(const std::vector<Entry> &entries)
{
    size_t size = entries.size();
    DBStatus status;
    for (size_t index = 0; index < size; index += MAX_BATCH_SIZE) {
        std::vector<Entry> dbEntries(
            entries.begin() + index, entries.begin() + std::min(index + MAX_BATCH_SIZE, size));
        status = kvStore_->PutBatch(dbEntries);
        if (status != DBStatus::OK) {
            ZLOGE("KvStore putBatch failed, status: %{public}d.", status);
            return E_DB_ERROR;
        }
    }
    return E_OK;
}

Status RuntimeStore::DeleteEntries(const std::vector<Key> &keys)
{
    size_t size = keys.size();
    DBStatus status;
    for (size_t index = 0; index < size; index += MAX_BATCH_SIZE) {
        std::vector<Key> dbKeys(keys.begin() + index, keys.begin() + std::min(index + MAX_BATCH_SIZE, size));
        status = kvStore_->DeleteBatch(dbKeys);
        if (status != DBStatus::OK) {
            ZLOGE("KvStore deleteBatch failed, status: %{public}d.", status);
            return E_DB_ERROR;
        }
    }
    return E_OK;
}

Status RuntimeStore::UnmarshalEntries(const std::string &key, std::vector<Entry> &entries, UnifiedData &unifiedData)
{
    for (const auto &entry : entries) {
        std::string keyStr = {entry.key.begin(), entry.key.end()};
        if (keyStr == key) {
            Runtime runtime;
            auto runtimeTlv = TLVObject(const_cast<std::vector<uint8_t> &>(entry.value));
            if (!TLVUtil::Reading(runtime, runtimeTlv)) {
                ZLOGE("Unmarshall runtime info failed.");
                return E_READ_PARCEL_ERROR;
            }
            unifiedData.SetRuntime(runtime);
        } else if (keyStr.find(key) == 0) {
            std::shared_ptr<UnifiedRecord> record;
            auto recordTlv = TLVObject(const_cast<std::vector<uint8_t> &>(entry.value));
            if (!TLVUtil::Reading(record, recordTlv)) {
                ZLOGE("Unmarshall unified record failed.");
                return E_READ_PARCEL_ERROR;
            }
            unifiedData.AddRecord(record);
        }
    }
    return E_OK;
}
} // namespace UDMF
} // namespace OHOS