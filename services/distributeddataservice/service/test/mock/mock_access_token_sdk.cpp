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
#include "access_token_mock.h"
#include "mock_access_token_state.h"

#include "token_setproc.h"
#include "tokenid_kit.h"

namespace OHOS::Security::AccessToken {
ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(AccessTokenID tokenID)
{
    if (BAccessTokenKit::accessTokenkit == nullptr) {
        return MockAccessTokenState::Type(tokenID);
    }
    return BAccessTokenKit::accessTokenkit->GetTokenTypeFlag(tokenID);
}

ATokenTypeEnum AccessTokenKit::GetTokenType(AccessTokenID tokenID)
{
    if (BAccessTokenKit::accessTokenkit == nullptr) {
        return MockAccessTokenState::Type(tokenID);
    }
    return BAccessTokenKit::accessTokenkit->GetTokenType(tokenID);
}

int AccessTokenKit::GetHapTokenInfo(AccessTokenID tokenID, HapTokenInfo& hapTokenInfoRes)
{
    if (BAccessTokenKit::accessTokenkit == nullptr) {
        return MockAccessTokenState::HapInfo(tokenID, hapTokenInfoRes);
    }
    return BAccessTokenKit::accessTokenkit->GetHapTokenInfo(tokenID, hapTokenInfoRes);
}

int AccessTokenKit::GetNativeTokenInfo(AccessTokenID tokenID, NativeTokenInfo& nativeTokenInfo)
{
    if (BAccessTokenKit::accessTokenkit == nullptr) {
        return MockAccessTokenState::NativeInfo(tokenID, nativeTokenInfo);
    }
    return BAccessTokenKit::accessTokenkit->GetNativeTokenInfo(tokenID, nativeTokenInfo);
}

int AccessTokenKit::VerifyAccessToken(AccessTokenID tokenID, const std::string& permissionName)
{
    if (BAccessTokenKit::accessTokenkit == nullptr) {
        return MockAccessTokenState::Verify(tokenID, permissionName);
    }
    return BAccessTokenKit::accessTokenkit->VerifyAccessToken(tokenID, permissionName);
}

bool TokenIdKit::IsSystemAppByFullTokenID(uint64_t tokenID)
{
    if (BTokenIdKit::tokenkIdKit == nullptr) {
        return MockAccessTokenState::IsSystem(tokenID);
    }
    return BTokenIdKit::tokenkIdKit->IsSystemAppByFullTokenID(tokenID);
}

AccessTokenIDEx AccessTokenKit::AllocHapToken(const HapInfoParams &info, const HapPolicyParams &policy)
{
    return MockAccessTokenState::Allocate(info, policy);
}

int32_t AccessTokenKit::InitHapToken(const HapInfoParams &info, HapPolicyParams &policy, AccessTokenIDEx &id)
{
    id = AllocHapToken(info, policy);
    return id.tokenIDEx == 0 ? RET_FAILED : RET_SUCCESS;
}

int32_t AccessTokenKit::InitHapToken(
    const HapInfoParams &info, HapPolicyParams &policy, AccessTokenIDEx &id, HapInfoCheckResult &result)
{
    return InitHapToken(info, policy, id);
}

AccessTokenID AccessTokenKit::GetHapTokenID(int user, const std::string &bundle, int instance)
{
    return MockAccessTokenState::FindHap(user, bundle, instance).tokenIdExStruct.tokenID;
}

int AccessTokenKit::DeleteToken(AccessTokenID token)
{
    return MockAccessTokenState::Delete(token);
}

int32_t AccessTokenKit::ReloadNativeTokenInfo()
{
    return RET_SUCCESS;
}

ATokenTypeEnum AccessTokenKit::GetTokenType(FullTokenID token)
{
    return GetTokenType(static_cast<AccessTokenID>(token));
}

ATokenTypeEnum AccessTokenKit::GetTokenTypeFlag(FullTokenID token)
{
    return GetTokenTypeFlag(static_cast<AccessTokenID>(token));
}

int AccessTokenKit::GrantPermission(
    AccessTokenID token, const std::string &permission, uint32_t flag, UpdatePermissionFlag updateFlag)
{
    return MockAccessTokenState::SetPermission(token, permission, PERMISSION_GRANTED);
}

int AccessTokenKit::RevokePermission(AccessTokenID token, const std::string &permission, uint32_t flag,
    UpdatePermissionFlag updateFlag, bool killProcess)
{
    return MockAccessTokenState::SetPermission(token, permission, PERMISSION_DENIED);
}

bool AccessTokenKit::IsSystemAppByFullTokenID(uint64_t token)
{
    return TokenIdKit::IsSystemAppByFullTokenID(token);
}
} // namespace OHOS::Security::AccessToken

uint64_t GetAccessTokenId(NativeTokenInfoParams *info)
{
    return info == nullptr ? 0 : OHOS::Security::AccessToken::MockAccessTokenState::AllocateNative(*info);
}

uint64_t GetSelfTokenID()
{
    return OHOS::Security::AccessToken::MockAccessTokenState::Self();
}

int SetSelfTokenID(uint64_t token)
{
    OHOS::Security::AccessToken::MockAccessTokenState::SetSelf(token);
    return 0;
}
