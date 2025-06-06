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
#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_METADATA_STORE_META_DATA_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_METADATA_STORE_META_DATA_H

#include <vector>

#include "serializable/serializable.h"
#include "store/store_info.h"

namespace OHOS::DistributedData {
struct API_EXPORT StoreMetaData final : public Serializable {
    // record meta version for compatible, should update when modify store meta data structure.
    static constexpr uint32_t CURRENT_VERSION = 0x03000006;
    // UID -> uid, deviceAccountId -> userId, userId -> user
    static constexpr uint32_t FIELD_CHANGED_TAG = 0x03000003;
    static constexpr uint32_t UUID_CHANGED_TAG = 0x03000004;
    static constexpr const char *KEY_PREFIX = "KvStoreMetaData";
    static constexpr const char *ROOT_USER = "0";
    uint32_t version = CURRENT_VERSION;
    bool isAutoSync = false;
    bool isBackup = false;
    bool isDirty = false;
    bool isEncrypt = false;
    bool isManualClean = false;
    bool isSearchable = false;
    bool isNeedCompress = false;
    bool enableCloud = false;
    bool cloudAutoSync = false;
    int32_t dataType = -1;
    int32_t storeType = -1;
    int32_t securityLevel = 0;
    int32_t area = 0;
    int32_t uid = -1;
    int32_t instanceId = 0;
    int32_t haMode = 0;
    uint32_t tokenId = 0;
    std::string appId = "";
    std::string appType = "";
    std::string bundleName = "";
    std::string hapName = "";
    std::string dataDir = "";
    std::string customDir = "";
    std::string deviceId = "";
    std::string schema = "";
    std::string storeId = "";
    std::string user = "";
    std::string account = "";
    int32_t authType = 0;
    bool asyncDownloadAsset = false;
    bool isNeedUpdateDeviceId = false;

    enum StoreType {
        STORE_KV_BEGIN = 0,
        STORE_KV_END = 9,
        STORE_RELATIONAL_BEGIN = 10,
        STORE_RELATIONAL_END = 19,
        STORE_OBJECT_BEGIN = 20,
        STORE_OBJECT_END = 29,
        STORE_BUTT = 255
    };

    API_EXPORT StoreMetaData();
    API_EXPORT StoreMetaData(const std::string &userId, const std::string &appId, const std::string &storeId);
    API_EXPORT explicit StoreMetaData(const StoreInfo &storeInfo);
    API_EXPORT ~StoreMetaData();
    API_EXPORT bool operator==(const StoreMetaData &metaData) const;
    API_EXPORT bool operator!=(const StoreMetaData &metaData) const;
    API_EXPORT bool Marshal(json &node) const override;
    API_EXPORT bool Unmarshal(const json &node) override;
    API_EXPORT std::string GetKey() const;
    API_EXPORT std::string GetKeyLocal() const;
    API_EXPORT std::string GetSecretKey() const;
    API_EXPORT std::string GetStrategyKey() const;
    API_EXPORT std::string GetBackupSecretKey() const;
    API_EXPORT std::string GetAutoLaunchKey() const;
    API_EXPORT std::string GetDebugInfoKey() const;
    API_EXPORT std::string GetDfxInfoKey() const;
    API_EXPORT std::string GetStoreAlias() const;
    API_EXPORT StoreInfo GetStoreInfo() const;
    API_EXPORT static std::string GetKey(const std::initializer_list<std::string> &fields);
    API_EXPORT static std::string GetPrefix(const std::initializer_list<std::string> &fields);
    API_EXPORT std::string GetCloneSecretKey() const;
};
} // namespace OHOS::DistributedData
#endif // OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_METADATA_STORE_META_DATA_H