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
#ifndef DISTRIBUTED_DATA_MOCK_ACCESS_TOKEN_STATE_H
#define DISTRIBUTED_DATA_MOCK_ACCESS_TOKEN_STATE_H

#include <memory>

#include "accesstoken_kit.h"
#include "nativetoken_kit.h"

namespace OHOS::Security::AccessToken {
// State belongs to this test process. None of these operations contacts an SA or the token driver.
class MockAccessTokenState final {
public:
    static void Save();
    static void Restore();
    static AccessTokenIDEx Allocate(const HapInfoParams &info, const HapPolicyParams &policy);
    static uint64_t AllocateNative(const NativeTokenInfoParams &info);
    static AccessTokenIDEx FindHap(int user, const std::string &bundle, int instance);
    static int Delete(AccessTokenID token);
    static ATokenTypeEnum Type(AccessTokenID token);
    static int HapInfo(AccessTokenID token, HapTokenInfo &info);
    static int NativeInfo(AccessTokenID token, NativeTokenInfo &info);
    static int Verify(AccessTokenID token, const std::string &permission);
    static int SetPermission(AccessTokenID token, const std::string &permission, int status);
    static bool IsSystem(uint64_t token);
    static uint64_t Self();
    static void SetSelf(uint64_t token);
};

class ScopedMockToken final {
public:
    explicit ScopedMockToken(uint64_t token) : previous_(MockAccessTokenState::Self())
    {
        MockAccessTokenState::SetSelf(token);
    }
    ~ScopedMockToken()
    {
        MockAccessTokenState::SetSelf(previous_);
    }
    ScopedMockToken(const ScopedMockToken &) = delete;
    ScopedMockToken &operator=(const ScopedMockToken &) = delete;
private:
    uint64_t previous_;
};
} // namespace OHOS::Security::AccessToken
#endif // DISTRIBUTED_DATA_MOCK_ACCESS_TOKEN_STATE_H
