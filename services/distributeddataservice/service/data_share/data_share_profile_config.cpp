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
#define LOG_TAG "DataShareProfileConfig"

#include "data_share_profile_config.h"

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <sstream>
#include <string>
#include <unistd.h>

#include "bundle_mgr_proxy.h"
#include "datashare_errno.h"
#include "log_print.h"
#include "uri_utils.h"
#include "utils/anonymous.h"
#include "log_debug.h"

namespace OHOS {
namespace DataShare {
constexpr const char *PROFILE_FILE_PREFIX = "$profile:";
constexpr const char *SEPARATOR = "/";
static constexpr int PATH_SIZE = 2;
static constexpr int MAX_ALLOWLIST_COUNT = 256;
const size_t PROFILE_PREFIX_LEN = strlen(PROFILE_FILE_PREFIX);
bool Config::Marshal(json &node) const
{
    SetValue(node[GET_NAME(uri)], uri);
    SetValue(node[GET_NAME(crossUserMode)], crossUserMode);
    SetValue(node[GET_NAME(readPermission)], readPermission);
    SetValue(node[GET_NAME(writePermission)], writePermission);
    return true;
}

bool Config::Unmarshal(const json &node)
{
    bool ret = GetValue(node, GET_NAME(uri), uri);
    GetValue(node, GET_NAME(crossUserMode), crossUserMode);
    GetValue(node, GET_NAME(readPermission), readPermission);
    GetValue(node, GET_NAME(writePermission), writePermission);
    return ret;
}

bool LaunchInfo::Marshal(json &node) const
{
    SetValue(node[GET_NAME(storeId)], storeId);
    SetValue(node[GET_NAME(tableNames)], tableNames);
    return true;
}

bool LaunchInfo::Unmarshal(const json &node)
{
    GetValue(node, GET_NAME(storeId), storeId);
    GetValue(node, GET_NAME(tableNames), tableNames);
    return true;
}

bool AllowList::Marshal(json &node) const
{
    SetValue(node[GET_NAME(appIdentifier)], appIdentifier);
    SetValue(node[GET_NAME(onlyMain)], onlyMain);
    return true;
}

bool AllowList::Unmarshal(const json &node)
{
    // when onlyMain is invalid, do not get appIdentifier, or if appIdentifier matched, onlyMain may not be expected
    if (GetValue(node, GET_NAME(onlyMain), onlyMain)) {
        GetValue(node, GET_NAME(appIdentifier), appIdentifier);
    }
    return true;
}

bool ProfileInfo::Marshal(json &node) const
{
    SetValue(node[GET_NAME(tableConfig)], tableConfig);
    SetValue(node[GET_NAME(isSilentProxyEnable)], isSilentProxyEnable);
    SetValue(node[GET_NAME(path)], storeName + SEPARATOR + tableName);
    SetValue(node[GET_NAME(scope)], scope);
    SetValue(node[GET_NAME(type)], type);
    SetValue(node[GET_NAME(launchInfos)], launchInfos);
    SetValue(node[GET_NAME(allowLists)], allowLists);
    SetValue(node[GET_NAME(storeMetaDataFromUri)], storeMetaDataFromUri);
    SetValue(node[GET_NAME(launchForCleanData)], launchForCleanData);
    SetValue(node[GET_NAME(backup)], backup);
    SetValue(node[GET_NAME(extUri)], extUri);
    return true;
}

bool ProfileInfo::Unmarshal(const json &node)
{
    GetValue(node, GET_NAME(tableConfig), tableConfig);
    GetValue(node, GET_NAME(isSilentProxyEnable), isSilentProxyEnable);
    GetValue(node, GET_NAME(scope), scope);
    GetValue(node, GET_NAME(type), type);
    GetValue(node, GET_NAME(launchInfos), launchInfos);
    GetValue(node, GET_NAME(allowLists), allowLists);
    if (allowLists.size() > MAX_ALLOWLIST_COUNT) {
        allowLists.resize(MAX_ALLOWLIST_COUNT);
    }
    GetValue(node, GET_NAME(storeMetaDataFromUri), storeMetaDataFromUri);
    GetValue(node, GET_NAME(launchForCleanData), launchForCleanData);
    GetValue(node, GET_NAME(backup), backup);
    GetValue(node, GET_NAME(extUri), extUri);
    std::string path;
    auto ret = GetValue(node, GET_NAME(path), path);
    if (ret) {
        std::vector<std::string> splitPath;
        SplitStr(path, SEPARATOR, splitPath);
        if (splitPath.size() < PATH_SIZE) {
            return false;
        }

        if (splitPath[0].empty() || splitPath[1].empty()) {
            return false;
        }
        storeName = splitPath[0];
        tableName = splitPath[1];
    }
    return true;
}

bool SerialDataShareProxyData::Marshal(json &node) const
{
    SetValue(node[GET_NAME(uri)], uri);
    SetValue(node[GET_NAME(value)], value);
    SetValue(node[GET_NAME(allowList)], allowList);
    return true;
}

bool SerialDataShareProxyData::Unmarshal(const json &node)
{
    bool ret = GetValue(node, GET_NAME(uri), uri);
    // the value in profile can only be string, but the type of value which is published is variant,
    // use type variant to unmarshal a string will fail, so use a string to try unmarshal again
    if (!GetValue(node, GET_NAME(value), value)) {
        std::string valueStr;
        GetValue(node, GET_NAME(value), valueStr);
        value = valueStr;
    }
    GetValue(node, GET_NAME(allowList), allowList);
    return ret;
}

bool ProxyDataProfileInfo::Marshal(json &node) const
{
    SetValue(node[GET_NAME(crossAppSharedConfig)], dataShareProxyDatas);
    return true;
}

bool ProxyDataProfileInfo::Unmarshal(const json &node)
{
    bool ret = GetValue(node, GET_NAME(crossAppSharedConfig), dataShareProxyDatas);
    return ret;
}

std::pair<int, ProfileInfo> DataShareProfileConfig::GetDataProperties(
    const std::vector<AppExecFwk::Metadata> &metadata, const std::string &resPath,
    const std::string &hapPath, const std::string &name)
{
    ProfileInfo profileInfo;
    std::string resourcePath = !hapPath.empty() ? hapPath : resPath;
    std::string info = GetProfileInfoByMetadata(metadata, resourcePath, hapPath, name);
    if (info.empty()) {
        return std::make_pair(NOT_FOUND, profileInfo);
    }
    if (!profileInfo.Unmarshall(info)) {
        return std::make_pair(ERROR, profileInfo);
    }
    return std::make_pair(SUCCESS, profileInfo);
}

std::pair<int, std::vector<SerialDataShareProxyData>> DataShareProfileConfig::GetCrossAppSharedConfig(
    const std::string &resource, const std::string &resPath, const std::string &hapPath)
{
    std::vector<SerialDataShareProxyData> serialProxyDatas;
    ProxyDataProfileInfo profileInfo;
    std::string resourcePath = !hapPath.empty() ? hapPath : resPath;

    std::shared_ptr<ResourceManager> resMgr = InitResMgr(resourcePath);
    if (resMgr == nullptr) {
        return std::make_pair(ERROR, serialProxyDatas);
    }
    std::string info = GetResFromResMgr(resource, *resMgr, hapPath);
    if (info.empty()) {
        return std::make_pair(NOT_FOUND, serialProxyDatas);
    }
    if (!profileInfo.Unmarshall(info)) {
        return std::make_pair(ERROR, serialProxyDatas);
    }
    return std::make_pair(SUCCESS, profileInfo.dataShareProxyDatas);
}

std::string DataShareProfileConfig::GetProfileInfoByMetadata(const std::vector<AppExecFwk::Metadata> &metadata,
    const std::string &resourcePath, const std::string &hapPath, const std::string &name)
{
    std::string profileInfo;
    if (metadata.empty() || resourcePath.empty()) {
        return profileInfo;
    }
    auto it = std::find_if(metadata.begin(), metadata.end(), [&name](AppExecFwk::Metadata meta) {
        return meta.name == name;
    });
    if (it != metadata.end()) {
        std::shared_ptr<ResourceManager> resMgr = InitResMgr(resourcePath);
        if (resMgr == nullptr) {
            return profileInfo;
        }
        return GetResFromResMgr((*it).resource, *resMgr, hapPath);
    }

    return profileInfo;
}

std::shared_ptr<ResourceManager> DataShareProfileConfig::InitResMgr(const std::string &resourcePath)
{
    std::shared_ptr<ResourceManager> resMgr(CreateResourceManager(false));
    if (resMgr == nullptr) {
        return nullptr;
    }

    std::unique_ptr<ResConfig> resConfig(CreateResConfig());
    if (resConfig == nullptr) {
        return nullptr;
    }
    resMgr->UpdateResConfig(*resConfig);
    resMgr->AddResource(resourcePath.c_str());
    return resMgr;
}

std::string DataShareProfileConfig::GetResFromResMgr(
    const std::string &resName, ResourceManager &resMgr, const std::string &hapPath)
{
    std::string profileInfo;
    if (resName.empty()) {
        return profileInfo;
    }

    size_t pos = resName.rfind(PROFILE_FILE_PREFIX);
    if ((pos == std::string::npos) || (pos == resName.length() - PROFILE_PREFIX_LEN)) {
        ZLOGE("res name invalid, resName is %{public}s", resName.c_str());
        return profileInfo;
    }
    std::string profileName = resName.substr(pos + PROFILE_PREFIX_LEN);
    // hap is compressed status, get file content.
    if (!hapPath.empty()) {
        ZLOGD_MACRO("compressed status.");
        std::unique_ptr<uint8_t[]> fileContent = nullptr;
        size_t len = 0;
        RState ret = resMgr.GetProfileDataByName(profileName.c_str(), len, fileContent);
        if (ret != RState::SUCCESS || fileContent == nullptr) {
            ZLOGE("failed, ret is %{public}d, profileName is %{public}s", ret, profileName.c_str());
            return profileInfo;
        }
        if (len == 0) {
            ZLOGE("fileContent is empty, profileName is %{public}s", profileName.c_str());
            return profileInfo;
        }
        std::string rawData(fileContent.get(), fileContent.get() + len);
        if (!Config::IsJson(rawData)) {
            ZLOGE("rawData is not json, profileName is %{public}s", profileName.c_str());
            return profileInfo;
        }
        return rawData;
    }
    // hap is decompressed status, get file path then read file.
    std::string resPath;
    RState ret = resMgr.GetProfileByName(profileName.c_str(), resPath);
    if (ret != RState::SUCCESS) {
        ZLOGE("profileName not found, ret is %{public}d, profileName is %{public}s", ret, profileName.c_str());
        return profileInfo;
    }
    std::string profile = ReadProfile(resPath);
    if (profile.empty()) {
        ZLOGE("Read profile failed, resPath is %{public}s", resPath.c_str());
        return profileInfo;
    }
    return profile;
}

bool DataShareProfileConfig::IsFileExisted(const std::string &filePath)
{
    if (filePath.empty()) {
        return false;
    }
    if (access(filePath.c_str(), F_OK) != 0) {
        ZLOGE("can not access file, errno is %{public}d, filePath is %{public}s", errno, filePath.c_str());
        return false;
    }
    return true;
}

std::string DataShareProfileConfig::ReadProfile(const std::string &resPath)
{
    if (!IsFileExisted(resPath)) {
        return "";
    }
    std::fstream in;
    in.open(resPath, std::ios_base::in | std::ios_base::binary);
    if (!in.is_open()) {
        ZLOGE("the file can not open, errno is %{public}d", errno);
        return "";
    }
    std::ostringstream tmp;
    tmp << in.rdbuf();
    std::string content = tmp.str();
    if (content.empty()) {
        ZLOGE("the file is empty, resPath is %{public}s", resPath.c_str());
        return "";
    }
    return content;
}

bool DataShareProfileConfig::GetProfileInfo(const std::string &calledBundleName, int32_t currentUserId,
    std::map<std::string, ProfileInfo> &profileInfos)
{
    BundleConfig bundleInfo;
    // profile is the same when app clone
    if (BundleMgrProxy::GetInstance()->GetBundleInfoFromBMSWithCheck(calledBundleName,
        currentUserId, bundleInfo) != E_OK) {
        ZLOGE("data share GetBundleInfoFromBMSWithCheck failed! bundleName: %{public}s, currentUserId = %{public}d",
              calledBundleName.c_str(), currentUserId);
        return false;
    }
    for (auto &item : bundleInfo.extensionInfos) {
        if (item.type != AppExecFwk::ExtensionAbilityType::DATASHARE) {
            continue;
        }
        auto profileInfo = item.profileInfo;
        if (profileInfo.resultCode == ERROR || profileInfo.resultCode == NOT_FOUND) {
            continue;
        }
        profileInfos[item.uri] = profileInfo.profile;
    }
    return true;
}

AccessCrossMode DataShareProfileConfig::GetAccessCrossMode(const ProfileInfo &profileInfo,
    const std::string &tableUri, const std::string &storeUri)
{
    auto crossMode = std::make_pair(AccessCrossMode::USER_UNDEFINED, DataShareProfileConfig::UNDEFINED_PRIORITY);
    for (auto const &item : profileInfo.tableConfig) {
        if (item.uri == tableUri) {
            SetCrossUserMode(TABLE_MATCH_PRIORITY, item.crossUserMode, crossMode);
            continue;
        }
        if (item.uri == storeUri) {
            SetCrossUserMode(STORE_MATCH_PRIORITY, item.crossUserMode, crossMode);
            continue;
        }
        if (item.uri == "*") {
            SetCrossUserMode(COMMON_MATCH_PRIORITY, item.crossUserMode, crossMode);
            continue;
        }
    }
    if (crossMode.second != UNDEFINED_PRIORITY) {
        return crossMode.first;
    }
    return AccessCrossMode::USER_UNDEFINED;
}

void DataShareProfileConfig::SetCrossUserMode(uint8_t priority, uint8_t crossMode,
    std::pair<AccessCrossMode, int8_t> &mode)
{
    if (mode.second < priority && crossMode > AccessCrossMode::USER_UNDEFINED &&
        crossMode < AccessCrossMode::USER_MAX) {
        mode.first = static_cast<AccessCrossMode>(crossMode);
        mode.second = priority;
    }
}
} // namespace DataShare
} // namespace OHOS

