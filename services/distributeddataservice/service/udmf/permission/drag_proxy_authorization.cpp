/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "drag_proxy_authorization.h"

#include "accesstoken_kit.h"
#include "bundle_mgr_client.h"

namespace OHOS::UDMF {
namespace {
using namespace Security::AccessToken;

constexpr const char *FILE_MANAGER_BUNDLE_NAME = "com.huawei.hmos.filemanager";
constexpr const char *DESKTOP_BUNDLE_NAME = "com.ohos.sceneboard";

bool GetHapTokenInfo(uint32_t tokenId, HapTokenInfo &tokenInfo)
{
    return tokenId != 0 && AccessTokenKit::GetTokenTypeFlag(tokenId) == TOKEN_HAP &&
           AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo) == RET_SUCCESS;
}
} // namespace

bool DragProxyAuthorization::IsAuthorized(uint32_t requesterTokenId, const std::vector<uint32_t> &authorizedTokenIds)
{
    HapTokenInfo requesterInfo;
    if (!GetHapTokenInfo(requesterTokenId, requesterInfo) || requesterInfo.bundleName != FILE_MANAGER_BUNDLE_NAME) {
        return false;
    }
    for (uint32_t authorizedTokenId : authorizedTokenIds) {
        HapTokenInfo authorizedInfo;
        if (GetHapTokenInfo(authorizedTokenId, authorizedInfo) && authorizedInfo.bundleName == DESKTOP_BUNDLE_NAME &&
            authorizedInfo.userID == requesterInfo.userID) {
            return true;
        }
    }
    return false;
}

bool DragProxyAuthorization::GetFileManagerProxyUid(uint32_t authorizedTokenId, int32_t &proxyUid)
{
    proxyUid = -1;
    HapTokenInfo authorizedInfo;
    if (!GetHapTokenInfo(authorizedTokenId, authorizedInfo) || authorizedInfo.bundleName != DESKTOP_BUNDLE_NAME) {
        return false;
    }
    AppExecFwk::BundleMgrClient bundleMgrClient;
    AppExecFwk::BundleInfo bundleInfo;
    if (!bundleMgrClient.GetBundleInfo(FILE_MANAGER_BUNDLE_NAME, AppExecFwk::GET_BUNDLE_DEFAULT, bundleInfo,
        authorizedInfo.userID) || bundleInfo.applicationInfo.uid < 0) {
        return false;
    }
    proxyUid = bundleInfo.applicationInfo.uid;
    return true;
}
} // namespace OHOS::UDMF
