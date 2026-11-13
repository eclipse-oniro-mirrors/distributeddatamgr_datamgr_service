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
#include "native_and_hap_token_mock.h"

#include "nativetoken_kit.h"

namespace OHOS::DistributedData {
using namespace Security::AccessToken;

void MockToken::SetTestEnvironment()
{
    // The access-token provider is linked into this TDD executable; no privileged identity is needed.
}

void MockToken::ResetTestEnvironment()
{
}

MockNativeToken::MockNativeToken(const std::string &process) : selfToken_(GetSelfTokenID())
{
    SetSelfTokenID(MockToken::GetTokenByProcName(process));
}

MockNativeToken::~MockNativeToken()
{
    SetSelfTokenID(selfToken_);
}

AccessTokenID MockToken::GetTokenByProcName(const std::string &process)
{
    NativeTokenInfoParams info{};
    info.processName = process.c_str();
    return static_cast<AccessTokenID>(GetAccessTokenId(&info));
}

AccessTokenIDEx MockToken::AllocTestHapToken(const HapInfoParams &info, HapPolicyParams &policy)
{
    AccessTokenIDEx id{};
    AccessTokenKit::InitHapToken(info, policy, id);
    return id;
}

int32_t MockToken::DeleteTestHapToken(AccessTokenID token)
{
    return AccessTokenKit::DeleteToken(token);
}
} // namespace OHOS::DistributedData
