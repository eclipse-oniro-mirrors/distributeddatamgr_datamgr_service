/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef NATIVE_AND_HAP_TOKEN_MOCK_H
#define NATIVE_AND_HAP_TOKEN_MOCK_H

#include <gtest/gtest.h>
#include "access_token.h"
#include "accesstoken_kit.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedData {
using namespace OHOS;

// Helpers use the process-local AccessToken mock linked by the TDD target.
class MockNativeToken {
public:
    explicit MockNativeToken(const std::string& process);
    ~MockNativeToken();
private:
    uint64_t selfToken_;
};

class MockToken {
public:
    // Retained fixture entry point; per-test state isolation is provided by the mock listener.
    static void SetTestEnvironment();
    // Retained fixture exit point. No real process token is modified.
    static void ResetTestEnvironment();
    // Register a simulated native identity independently of device process availability.
    static Security::AccessToken::AccessTokenID GetTokenByProcName(const std::string& process);
    static Security::AccessToken::AccessTokenIDEx AllocTestHapToken(
        const Security::AccessToken::HapInfoParams& hapInfo, Security::AccessToken::HapPolicyParams& hapPolicy
    );
    // Delete a token from this test process only.
    static int32_t DeleteTestHapToken(Security::AccessToken::AccessTokenID tokenID);
};
}
}
#endif // NATIVE_AND_HAP_TOKEN_MOCK_H