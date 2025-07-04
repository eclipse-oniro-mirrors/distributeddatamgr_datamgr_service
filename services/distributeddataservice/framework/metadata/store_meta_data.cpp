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

#include "metadata/store_meta_data.h"

#include "metadata/auto_launch_meta_data.h"
#include "metadata/secret_key_meta_data.h"
#include "metadata/store_debug_info.h"
#include "metadata/store_meta_data_local.h"
#include "metadata/strategy_meta_data.h"
#include "utils/anonymous.h"
#include "utils/constant.h"
#include "utils/crypto.h"
namespace OHOS {
namespace DistributedData {
constexpr uint32_t StoreMetaData::CURRENT_VERSION;
constexpr uint32_t StoreMetaData::FIELD_CHANGED_TAG;
constexpr const char *StoreMetaData::KEY_PREFIX;
bool StoreMetaData::Marshal(json &node) const
{
    SetValue(node[GET_NAME(version)], version);
    SetValue(node[GET_NAME(isAutoSync)], isAutoSync);
    SetValue(node[GET_NAME(isBackup)], isBackup);
    SetValue(node[GET_NAME(isEncrypt)], isEncrypt);
    SetValue(node[GET_NAME(isManualClean)], isManualClean);
    SetValue(node[GET_NAME(isDirty)], isDirty);
    SetValue(node[GET_NAME(isSearchable)], isSearchable);
    SetValue(node[GET_NAME(isNeedCompress)], isNeedCompress);
    SetValue(node[GET_NAME(storeType)], storeType);
    SetValue(node[GET_NAME(securityLevel)], securityLevel);
    SetValue(node[GET_NAME(area)], area);
    SetValue(node[GET_NAME(uid)], uid);
    SetValue(node[GET_NAME(tokenId)], tokenId);
    SetValue(node[GET_NAME(instanceId)], instanceId);
    SetValue(node[GET_NAME(appId)], appId);
    SetValue(node[GET_NAME(appType)], appType);
    SetValue(node[GET_NAME(bundleName)], bundleName);
    SetValue(node[GET_NAME(hapName)], hapName);
    SetValue(node[GET_NAME(dataDir)], dataDir);
    SetValue(node[GET_NAME(deviceId)], deviceId);
    SetValue(node[GET_NAME(schema)], schema);
    SetValue(node[GET_NAME(storeId)], storeId);
    SetValue(node[GET_NAME(user)], user);
    SetValue(node[GET_NAME(account)], account);
    SetValue(node[GET_NAME(dataType)], dataType);
    SetValue(node[GET_NAME(enableCloud)], enableCloud);
    SetValue(node[GET_NAME(cloudAutoSync)], cloudAutoSync);
    SetValue(node[GET_NAME(asyncDownloadAsset)], asyncDownloadAsset);
    SetValue(node[GET_NAME(isNeedUpdateDeviceId)], isNeedUpdateDeviceId);
    // compatible with the versions which lower than VERSION_TAG_0000
    SetValue(node[GET_NAME(kvStoreType)], storeType);
    SetValue(node[GET_NAME(deviceAccountID)], user);
    SetValue(node[GET_NAME(userId)], account);
    SetValue(node[GET_NAME(UID)], uid);
    SetValue(node[GET_NAME(customDir)], customDir);
    SetValue(node[GET_NAME(authType)], authType);
    SetValue(node[GET_NAME(haMode)], haMode);
    return true;
}

bool StoreMetaData::Unmarshal(const json &node)
{
    GetValue(node, GET_NAME(version), version);
    GetValue(node, GET_NAME(isAutoSync), isAutoSync);
    GetValue(node, GET_NAME(isBackup), isBackup);
    GetValue(node, GET_NAME(isDirty), isDirty);
    GetValue(node, GET_NAME(isEncrypt), isEncrypt);
    GetValue(node, GET_NAME(isManualClean), isManualClean);
    GetValue(node, GET_NAME(isSearchable), isSearchable);
    GetValue(node, GET_NAME(isNeedCompress), isNeedCompress);
    GetValue(node, GET_NAME(storeType), storeType);
    GetValue(node, GET_NAME(securityLevel), securityLevel);
    GetValue(node, GET_NAME(area), area);
    GetValue(node, GET_NAME(uid), uid);
    GetValue(node, GET_NAME(tokenId), tokenId);
    GetValue(node, GET_NAME(instanceId), instanceId);
    GetValue(node, GET_NAME(appId), appId);
    GetValue(node, GET_NAME(appType), appType);
    GetValue(node, GET_NAME(bundleName), bundleName);
    GetValue(node, GET_NAME(hapName), hapName);
    GetValue(node, GET_NAME(dataDir), dataDir);
    GetValue(node, GET_NAME(deviceId), deviceId);
    GetValue(node, GET_NAME(schema), schema);
    GetValue(node, GET_NAME(storeId), storeId);
    GetValue(node, GET_NAME(user), user);
    GetValue(node, GET_NAME(account), account);
    GetValue(node, GET_NAME(dataType), dataType);
    GetValue(node, GET_NAME(enableCloud), enableCloud);
    GetValue(node, GET_NAME(cloudAutoSync), cloudAutoSync);
    GetValue(node, GET_NAME(asyncDownloadAsset), asyncDownloadAsset);
    GetValue(node, GET_NAME(isNeedUpdateDeviceId), isNeedUpdateDeviceId);
    // compatible with the older versions
    if (version < FIELD_CHANGED_TAG) {
        GetValue(node, GET_NAME(kvStoreType), storeType);
        GetValue(node, GET_NAME(UID), uid);
        GetValue(node, GET_NAME(deviceAccountID), user);
        GetValue(node, GET_NAME(userId), account);
    }
    GetValue(node, GET_NAME(customDir), customDir);
    GetValue(node, GET_NAME(authType), authType);
    GetValue(node, GET_NAME(haMode), haMode);
    return true;
}

StoreMetaData::StoreMetaData()
{
}

StoreMetaData::~StoreMetaData()
{
}

StoreMetaData::StoreMetaData(const std::string &userId, const std::string &appId, const std::string &storeId)
    : appId(appId), storeId(storeId), user(userId)
{
}

StoreMetaData::StoreMetaData(const StoreInfo &storeInfo)
    : instanceId(storeInfo.instanceId), bundleName(storeInfo.bundleName), dataDir(storeInfo.path),
      storeId(storeInfo.storeName), user(std::to_string(storeInfo.user))
{
}

bool StoreMetaData::operator==(const StoreMetaData &metaData) const
{
    if (Constant::NotEqual(isAutoSync, metaData.isAutoSync) || Constant::NotEqual(isBackup, metaData.isBackup) ||
        Constant::NotEqual(isDirty, metaData.isDirty) || Constant::NotEqual(isEncrypt, metaData.isEncrypt) ||
        Constant::NotEqual(isSearchable, metaData.isSearchable) ||
        Constant::NotEqual(isNeedCompress, metaData.isNeedCompress) ||
        Constant::NotEqual(enableCloud, metaData.enableCloud) ||
        Constant::NotEqual(cloudAutoSync, metaData.cloudAutoSync) ||
        Constant::NotEqual(isManualClean, metaData.isManualClean) ||
        Constant::NotEqual(isNeedUpdateDeviceId, metaData.isNeedUpdateDeviceId)) {
        return false;
    }
    return (version == metaData.version && storeType == metaData.storeType && dataType == metaData.dataType &&
            securityLevel == metaData.securityLevel && area == metaData.area && uid == metaData.uid &&
            tokenId == metaData.tokenId && instanceId == metaData.instanceId && appId == metaData.appId &&
            appType == metaData.appType && bundleName == metaData.bundleName && dataDir == metaData.dataDir &&
            storeId == metaData.storeId && user == metaData.user && deviceId == metaData.deviceId &&
            account == metaData.account && authType == metaData.authType && haMode == metaData.haMode);
}

bool StoreMetaData::operator!=(const StoreMetaData &metaData) const
{
    return !(*this == metaData);
}

std::string StoreMetaData::GetKey() const
{
    if (instanceId == 0) {
        return GetKey({ deviceId, user, "default", bundleName, storeId, dataDir });
    }
    return GetKey({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId), dataDir });
}

std::string StoreMetaData::GetKeyLocal() const
{
    if (instanceId == 0) {
        return StoreMetaDataLocal::GetKey({ deviceId, user, "default", bundleName, storeId, dataDir });
    }
    return StoreMetaDataLocal::GetKey(
        { deviceId, user, "default", bundleName, storeId, std::to_string(instanceId), dataDir });
}

std::string StoreMetaData::GetSecretKey() const
{
    if (version < UUID_CHANGED_TAG) {
        return SecretKeyMetaData::GetKey({ user, "default", bundleName, storeId, dataDir });
    }
    return SecretKeyMetaData::GetKey({ user, "default", bundleName, storeId, std::to_string(instanceId), dataDir });
}

std::string StoreMetaData::GetBackupSecretKey() const
{
    if (version < UUID_CHANGED_TAG) {
        return SecretKeyMetaData::GetBackupKey({ user, "default", bundleName, storeId });
    }
    return SecretKeyMetaData::GetBackupKey({ user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaData::GetAutoLaunchKey() const
{
    return AutoLaunchMetaData::GetPrefix({ deviceId, user, "default", bundleName, storeId });
}

std::string StoreMetaData::GetDebugInfoKey() const
{
    return StoreDebugInfo::GetPrefix(
        { deviceId, user, "default", bundleName, storeId, std::to_string(instanceId), dataDir });
}

std::string StoreMetaData::GetDebugInfoKeyWithoutPath() const
{
    return StoreDebugInfo::GetPrefix({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaData::GetDfxInfoKey() const
{
    return StoreDfxInfo::GetPrefix(
        { deviceId, user, "default", bundleName, storeId, std::to_string(instanceId), dataDir });
}

std::string StoreMetaData::GetDfxInfoKeyWithoutPath() const
{
    return StoreDfxInfo::GetPrefix({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaData::GetStoreAlias() const
{
    return Anonymous::Change(storeId);
}

std::string StoreMetaData::GetStrategyKey() const
{
    if (instanceId == 0) {
        return StrategyMeta::GetPrefix({ deviceId, user, "default", bundleName, storeId });
    }
    return StrategyMeta::GetPrefix({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaData::GetKey(const std::initializer_list<std::string> &fields)
{
    std::string prefix = KEY_PREFIX;
    for (const auto &field : fields) {
        prefix.append(Constant::KEY_SEPARATOR).append(field);
    }
    return prefix;
}

std::string StoreMetaData::GetPrefix(const std::initializer_list<std::string> &fields)
{
    return GetKey(fields).append(Constant::KEY_SEPARATOR);
}

StoreInfo StoreMetaData::GetStoreInfo() const
{
    StoreInfo info;
    info.instanceId = instanceId;
    info.bundleName = bundleName;
    info.storeName = storeId;
    info.user = atoi(user.c_str());
    return info;
}

std::string StoreMetaData::GetCloneSecretKey() const
{
    return SecretKeyMetaData::GetCloneKey({ user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaData::GetKeyWithoutPath() const
{
    if (instanceId == 0) {
        return GetKey({ deviceId, user, "default", bundleName, storeId });
    }
    return GetKey({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaData::GetKeyLocalWithoutPath() const
{
    if (instanceId == 0) {
        return StoreMetaDataLocal::GetKey({ deviceId, user, "default", bundleName, storeId });
    }
    return StoreMetaDataLocal::GetKey({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaData::GetSecretKeyWithoutPath() const
{
    if (version < UUID_CHANGED_TAG) {
        return SecretKeyMetaData::GetKey({ user, "default", bundleName, storeId });
    }
    return SecretKeyMetaData::GetKey({ user, "default", bundleName, storeId, std::to_string(instanceId) });
}

StoreMetaMapping::StoreMetaMapping() {}
StoreMetaMapping::StoreMetaMapping(const StoreMetaData &storeMeta) : StoreMetaData(storeMeta) {}
StoreMetaMapping::~StoreMetaMapping() {}

bool StoreMetaMapping::Marshal(json &node) const
{
    StoreMetaData::Marshal(node);
    SetValue(node[GET_NAME(cloudPath)], cloudPath);
    SetValue(node[GET_NAME(devicePath)], devicePath);
    SetValue(node[GET_NAME(searchPath)], searchPath);
    return true;
}
bool StoreMetaMapping::Unmarshal(const Serializable::json &node)
{
    StoreMetaData::Unmarshal(node);
    GetValue(node, GET_NAME(cloudPath), cloudPath);
    GetValue(node, GET_NAME(devicePath), devicePath);
    GetValue(node, GET_NAME(searchPath), searchPath);
    return true;
}

std::string StoreMetaMapping::GetKey() const
{
    if (instanceId == 0) {
        return GetKey({ deviceId, user, "default", bundleName, storeId });
    }
    return GetKey({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId) });
}

std::string StoreMetaMapping::GetCloudStoreMetaKey() const
{
    return GetStoreMetaKeyWithPath(cloudPath);
}

std::string StoreMetaMapping::GetDeviceStoreMetaKey() const
{
    return GetStoreMetaKeyWithPath(devicePath);
}

std::string StoreMetaMapping::GetSearchStoreMetaKey() const
{
    return GetStoreMetaKeyWithPath(searchPath);
}

std::string StoreMetaMapping::GetPrefix(const std::initializer_list<std::string> &fields)
{
    return GetKey(fields).append(Constant::KEY_SEPARATOR);
}

StoreMetaMapping& StoreMetaMapping::operator=(const StoreMetaData &meta)
{
    if (this == &meta) {
        return *this;
    }
    this->StoreMetaData::operator=(meta);
    return *this;
}

std::string StoreMetaMapping::GetStoreMetaKeyWithPath(const std::string &path) const
{
    if (instanceId == 0) {
        return StoreMetaData::GetKey({ deviceId, user, "default", bundleName, storeId, path });
    }
    return StoreMetaData::GetKey({ deviceId, user, "default", bundleName, storeId, std::to_string(instanceId), path });
}

std::string StoreMetaMapping::GetKey(const std::initializer_list<std::string> &fields)
{
    std::string prefix = KEY_PREFIX;
    for (const auto &field : fields) {
        prefix.append(Constant::KEY_SEPARATOR).append(field);
    }
    return prefix;
}
StoreMetaMapping::StoreMetaMapping(const StoreInfo &storeInfo) : StoreMetaData(storeInfo) {}

} // namespace DistributedData
} // namespace OHOS