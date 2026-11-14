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
#include "mock_access_token_state.h"

#include <gtest/gtest.h>

#include "ipc_skeleton.h"

namespace OHOS {
uint32_t IPCSkeleton::GetCallingTokenID()
{
    return static_cast<uint32_t>(Security::AccessToken::MockAccessTokenState::Self());
}

uint64_t IPCSkeleton::GetCallingFullTokenID()
{
    return Security::AccessToken::MockAccessTokenState::Self();
}

uint64_t IPCSkeleton::GetSelfTokenID()
{
    return Security::AccessToken::MockAccessTokenState::Self();
}

namespace {
class AccessTokenStateListener final : public testing::EmptyTestEventListener {
public:
    void OnTestStart(const testing::TestInfo &) override
    {
        Security::AccessToken::MockAccessTokenState::Save();
    }

    void OnTestEnd(const testing::TestInfo &) override
    {
        Security::AccessToken::MockAccessTokenState::Restore();
    }
};

const bool REGISTER_TOKEN_LISTENER = [] {
    testing::UnitTest::GetInstance()->listeners().Append(new AccessTokenStateListener());
    return true;
}();
} // namespace
} // namespace OHOS
