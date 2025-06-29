/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "DataProviderConfig"

#include "data_provider_config.h"

#include <vector>

#include "accesstoken_kit.h"
#include "account/account_delegate.h"
#include "config_factory.h"
#include "datashare_errno.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "log_print.h"
#include "strategies/general/load_config_common_strategy.h"
#include "tokenid_kit.h"
#include "uri_utils.h"
#include "utils/anonymous.h"

namespace OHOS::DataShare {
using namespace OHOS::DistributedData;
DataProviderConfig::DataProviderConfig(const std::string &uri, uint32_t callerTokenId)
{
    providerInfo_.uri = uri;
    providerInfo_.currentUserId = AccountDelegate::GetInstance()->GetUserByToken(callerTokenId);
    providerInfo_.visitedUserId = providerInfo_.currentUserId;
    URIUtils::GetAppIndexFromProxyURI(providerInfo_.uri, providerInfo_.appIndex);
    if (providerInfo_.currentUserId == 0) {
        LoadConfigCommonStrategy::GetInfoFromProxyURI(providerInfo_.uri, providerInfo_.visitedUserId,
            callerTokenId, providerInfo_.bundleName);
        URIUtils::FormatUri(providerInfo_.uri);
        // if visitedUserId is 0, set current foreground userId as visitedUserId
        if (providerInfo_.visitedUserId == 0) {
            if (!(AccountDelegate::GetInstance()->QueryForegroundUserId(providerInfo_.visitedUserId))) {
                ZLOGE("Get foreground userId failed");
            }
        }
    } else {
        auto [success, data] = URIUtils::GetUserFromProxyURI(providerInfo_.uri);
        if (success) {
            // if data is -1, it means visiting provider's user
            providerInfo_.visitedUserId = (data == -1 ? providerInfo_.currentUserId : data);
        } else {
            providerInfo_.visitedUserId = -1;
        }
    }
    uriConfig_ = URIUtils::GetUriConfig(providerInfo_.uri);
}

std::pair<int, BundleConfig> DataProviderConfig::GetBundleInfo()
{
    BundleConfig bundleInfo;
    providerInfo_.bundleName = uriConfig_.authority;
    if (providerInfo_.bundleName.empty()) {
        if (uriConfig_.pathSegments.empty()) {
            return std::make_pair(E_URI_NOT_EXIST, bundleInfo);
        }
        providerInfo_.bundleName = uriConfig_.pathSegments[0];
    }
    auto ret = BundleMgrProxy::GetInstance()->GetBundleInfoFromBMSWithCheck(
        providerInfo_.bundleName, providerInfo_.visitedUserId, bundleInfo, providerInfo_.appIndex);
    return std::make_pair(ret, bundleInfo);
}

int DataProviderConfig::GetFromProxyData()
{
    auto [errCode, bundleInfo] = GetBundleInfo();
    if (errCode != E_OK) {
        ZLOGE("Get bundleInfo failed! bundleName:%{public}s, userId:%{public}d, visitedId:%{public}d, uri:%{public}s",
            providerInfo_.bundleName.c_str(), providerInfo_.currentUserId, providerInfo_.visitedUserId,
            URIUtils::Anonymous(providerInfo_.uri).c_str());
        return errCode;
    }
    providerInfo_.singleton = bundleInfo.singleton;
    for (auto &item : bundleInfo.extensionInfos) {
        if (item.type != AppExecFwk::ExtensionAbilityType::DATASHARE) {
            continue;
        }
        providerInfo_.hasExtension = true;
        break;
    }
    for (auto &hapModuleInfo : bundleInfo.hapModuleInfos) {
        auto &proxyDatas = hapModuleInfo.proxyDatas;
        std::sort(proxyDatas.begin(), proxyDatas.end(), [](const ProxyData &curr,
            const ProxyData &prev) {
            return curr.uri.length() > prev.uri.length();
        });
        for (auto &data : proxyDatas) {
            if (data.uri.length() > uriConfig_.formatUri.length() ||
                uriConfig_.formatUri.compare(0, data.uri.length(), data.uri) != 0) {
                continue;
            }
            providerInfo_.readPermission = std::move(data.requiredReadPermission);
            providerInfo_.writePermission = std::move(data.requiredWritePermission);
            providerInfo_.allowLists = std::move(data.profileInfo.profile.allowLists);
            auto profileInfo = data.profileInfo;
            if (profileInfo.resultCode == NOT_FOUND) {
                return E_OK;
            }
            if (profileInfo.resultCode == ERROR) {
                ZLOGE("Profile unmarshall error.uri: %{public}s", URIUtils::Anonymous(providerInfo_.uri).c_str());
                return E_ERROR;
            }
            return GetFromDataProperties(profileInfo.profile, hapModuleInfo.moduleName);
        }
    }
    return E_URI_NOT_EXIST;
}

int DataProviderConfig::GetFromDataProperties(const ProfileInfo &profileInfo,
    const std::string &moduleName)
{
    if (profileInfo.scope == MODULE_SCOPE) {
        providerInfo_.moduleName = moduleName;
    }
    providerInfo_.storeName = profileInfo.storeName;
    providerInfo_.tableName = profileInfo.tableName;
    providerInfo_.type = profileInfo.type;
    providerInfo_.storeMetaDataFromUri = profileInfo.storeMetaDataFromUri;
    providerInfo_.backup = profileInfo.backup;
    providerInfo_.extensionUri = profileInfo.extUri;
    if (profileInfo.tableConfig.empty()) {
        return E_OK;
    }
    return GetFromExtensionProperties(profileInfo, moduleName);
}

int DataProviderConfig::GetFromExtensionProperties(const ProfileInfo &profileInfo,
    const std::string &moduleName)
{
    std::string storeUri = URIUtils::DATA_SHARE_SCHEMA + providerInfo_.bundleName + URIUtils::URI_SEPARATOR +
            moduleName + URIUtils::URI_SEPARATOR + providerInfo_.storeName;
    std::string tableUri = storeUri + URIUtils::URI_SEPARATOR + providerInfo_.tableName;
    providerInfo_.accessCrossMode = DataShareProfileConfig::GetAccessCrossMode(profileInfo, tableUri, storeUri);
    if (providerInfo_.singleton && providerInfo_.accessCrossMode == AccessCrossMode::USER_UNDEFINED) {
        ZLOGE("Single app must config user cross mode,bundleName:%{public}s, uri:%{public}s",
            providerInfo_.bundleName.c_str(), URIUtils::Anonymous(providerInfo_.uri).c_str());
        return E_ERROR;
    }
    if (providerInfo_.singleton && providerInfo_.accessCrossMode == AccessCrossMode::USER_SINGLE) {
        providerInfo_.tableName.append("_").append(std::to_string(providerInfo_.visitedUserId));
    }
    return E_OK;
}

int DataProviderConfig::GetFromExtension()
{
    providerInfo_.isFromExtension = true;
    if (!GetFromUriPath()) {
        ZLOGE("Uri path failed! uri:%{public}s", URIUtils::Anonymous(providerInfo_.uri).c_str());
        return E_URI_NOT_EXIST;
    }
    BundleConfig bundleInfo;
    auto ret = BundleMgrProxy::GetInstance()->GetBundleInfoFromBMSWithCheck(
        providerInfo_.bundleName, providerInfo_.visitedUserId, bundleInfo, providerInfo_.appIndex);
    if (ret != E_OK) {
        ZLOGE("BundleInfo failed! bundleName: %{public}s", providerInfo_.bundleName.c_str());
        return ret;
    }
    providerInfo_.singleton = bundleInfo.singleton;
    providerInfo_.allowEmptyPermission = true;
    for (auto &item : bundleInfo.extensionInfos) {
        if (item.type != AppExecFwk::ExtensionAbilityType::DATASHARE) {
            continue;
        }
        providerInfo_.hasExtension = true;
        providerInfo_.readPermission = std::move(item.readPermission);
        providerInfo_.writePermission = std::move(item.writePermission);
        auto profileInfo = item.profileInfo;
        if (profileInfo.resultCode == NOT_FOUND) {
            return E_OK;
        }
        if (profileInfo.resultCode == ERROR) {
            ZLOGE("Profile Unmarshall failed! uri:%{public}s", URIUtils::Anonymous(providerInfo_.uri).c_str());
            return E_ERROR;
        }
        return GetFromExtensionProperties(profileInfo.profile, providerInfo_.moduleName);
    }
    return E_URI_NOT_EXIST;
}

bool DataProviderConfig::GetFromUriPath()
{
    auto& pathSegments = uriConfig_.pathSegments;
    if (pathSegments.size() < static_cast<std::size_t>(PATH_PARAM::PARAM_SIZE) ||
        pathSegments[static_cast<std::size_t>(PATH_PARAM::BUNDLE_NAME)].empty() ||
        pathSegments[static_cast<std::size_t>(PATH_PARAM::MODULE_NAME)].empty() ||
        pathSegments[static_cast<std::size_t>(PATH_PARAM::STORE_NAME)].empty() ||
        pathSegments[static_cast<std::size_t>(PATH_PARAM::TABLE_NAME)].empty()) {
        ZLOGE("Invalid uri ! uri: %{public}s", URIUtils::Anonymous(providerInfo_.uri).c_str());
        return false;
    }
    providerInfo_.bundleName = pathSegments[static_cast<std::size_t>(PATH_PARAM::BUNDLE_NAME)];
    providerInfo_.moduleName = pathSegments[static_cast<std::size_t>(PATH_PARAM::MODULE_NAME)];
    providerInfo_.storeName = pathSegments[static_cast<std::size_t>(PATH_PARAM::STORE_NAME)];
    providerInfo_.tableName = pathSegments[static_cast<std::size_t>(PATH_PARAM::TABLE_NAME)];
    return true;
}

void DataProviderConfig::GetMetaDataFromUri()
{
    if (!providerInfo_.storeMetaDataFromUri) {
        return;
    }
    if (!GetFromUriPath()) {
        ZLOGE("Uri path failed, not change metaData from uri! uri:%{public}s",
            URIUtils::Anonymous(providerInfo_.uri).c_str());
    }
}

std::pair<int, DataProviderConfig::ProviderInfo> DataProviderConfig::GetProviderInfo()
{
    if (providerInfo_.appIndex == -1) {
        return std::make_pair(E_APPINDEX_INVALID, providerInfo_);
    }
    if (providerInfo_.visitedUserId == -1) {
        return std::make_pair(E_INVALID_USER_ID, providerInfo_);
    }
    auto ret = GetFromProxyData();
    if (ret == E_OK) {
        GetMetaDataFromUri();
        return std::make_pair(ret, providerInfo_);
    }
    if (ret != E_URI_NOT_EXIST) {
        return std::make_pair(ret, providerInfo_);
    }
    auto fullTokenId = IPCSkeleton::GetCallingFullTokenID();
    Security::AccessToken::HapTokenInfo tokenInfo;
    auto result = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(IPCSkeleton::GetCallingTokenID(), tokenInfo);
    if (!Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(fullTokenId)
        || (result == Security::AccessToken::RET_SUCCESS && !IsInExtList(tokenInfo.bundleName))) {
        ZLOGE("The URI in the extension, is not allowed for silent access.! ret: %{public}d, bundleName: %{public}s,"
            "uri: %{public}s", ret, tokenInfo.bundleName.c_str(), providerInfo_.uri.c_str());
    }
    ret = GetFromExtension();
    if (ret != E_OK) {
        ZLOGE("Get providerInfo failed! ret: %{public}d, uri: %{public}s",
            ret, URIUtils::Anonymous(providerInfo_.uri).c_str());
    }
    return std::make_pair(ret, providerInfo_);
}

bool DataProviderConfig::IsInExtList(const std::string &bundleName)
{
    DataShareConfig *config = ConfigFactory::GetInstance().GetDataShareConfig();
    if (config == nullptr) {
        return true;
    }
    std::vector<std::string>& extNames = config->dataShareExtNames;
    return std::find(extNames.begin(), extNames.end(), bundleName) != extNames.end();
}
} // namespace OHOS::DataShare
