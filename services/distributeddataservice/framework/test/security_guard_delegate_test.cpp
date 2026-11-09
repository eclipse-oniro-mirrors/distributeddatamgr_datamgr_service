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

#include "security_guard/security_guard_delegate.h"

#include <gtest/gtest.h>

using namespace testing::ext;
namespace OHOS::DistributedData {
namespace {
class UnavailableSecurityGuard final : public SecurityGuardDelegate {
public:
    Status Start() override
    {
        return Status::UNAVAILABLE;
    }
    bool IsReady() const override
    {
        return false;
    }
    DispatchStatus Request(const Event &, Completion) override
    {
        return DispatchStatus::UNAVAILABLE;
    }
    ClientSnapshot GetClientSnapshot() const override
    {
        return {};
    }
    void Stop() override
    {
    }
};
} // namespace
class SecurityGuardFrameworkDelegateTest : public testing::Test {};
/**
 * @tc.name: RegisterSecurityGuardInstance_FirstValidAndDuplicate_PreservesProcessInstance
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardFrameworkDelegateTest,
    RegisterSecurityGuardInstance_FirstValidAndDuplicate_PreservesProcessInstance, TestSize.Level1)
{
    EXPECT_EQ(SecurityGuardDelegate::GetInstance(), nullptr);
    EXPECT_FALSE(SecurityGuardDelegate::RegisterSecurityGuardInstance(nullptr));
    static UnavailableSecurityGuard original;
    static UnavailableSecurityGuard replacement;
    ASSERT_TRUE(SecurityGuardDelegate::RegisterSecurityGuardInstance(&original));
    EXPECT_EQ(SecurityGuardDelegate::GetInstance(), &original);
    EXPECT_FALSE(SecurityGuardDelegate::RegisterSecurityGuardInstance(&original));
    EXPECT_FALSE(SecurityGuardDelegate::RegisterSecurityGuardInstance(&replacement));
    EXPECT_FALSE(SecurityGuardDelegate::RegisterSecurityGuardInstance(nullptr));
    EXPECT_EQ(SecurityGuardDelegate::GetInstance(), &original);
}
/**
 * @tc.name: HasSubscribers_UnknownSnapshot_RequiresAuthoritativeRequest
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    SecurityGuardFrameworkDelegateTest, HasSubscribers_UnknownSnapshot_RequiresAuthoritativeRequest, TestSize.Level1)
{
    SecurityGuardDelegate::ClientSnapshot snapshot;
    EXPECT_TRUE(snapshot.HasSubscribers(INT64_C(5000000001)));
    snapshot.policies[1] = {};
    EXPECT_TRUE(snapshot.HasSubscribers(1));
    EXPECT_TRUE(snapshot.HasSubscribers(2));
}
/**
 * @tc.name: HasSubscribers_InitializedMissingOrEmptyEvent_DoesNotDispatch
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    SecurityGuardFrameworkDelegateTest, HasSubscribers_InitializedMissingOrEmptyEvent_DoesNotDispatch, TestSize.Level1)
{
    SecurityGuardDelegate::ClientSnapshot snapshot;
    snapshot.initialized = true;
    snapshot.policies[1] = {};
    snapshot.policies[2] = { { SecurityGuardDelegate::Strategy::DENY, 400 } };
    EXPECT_FALSE(snapshot.HasSubscribers(1));
    EXPECT_FALSE(snapshot.HasSubscribers(3));
    EXPECT_TRUE(snapshot.HasSubscribers(2));
}
/**
 * @tc.name: HasSubscribers_Int64EventAndCopiedSnapshot_PreservesIdentityAndIsolation
 * @tc.desc: Verify the public contract and observable side effects for this branch.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardFrameworkDelegateTest, HasSubscribers_Int64EventAndCopiedSnapshot_PreservesIdentityAndIsolation,
    TestSize.Level1)
{
    constexpr int64_t eventId = INT64_C(5000000001);
    SecurityGuardDelegate::ClientSnapshot snapshot;
    snapshot.initialized = true;
    snapshot.version = 19;
    snapshot.policies[eventId] = { { SecurityGuardDelegate::Strategy::ALLOW, 400 } };
    auto copied = snapshot;
    snapshot.policies[eventId].clear();
    EXPECT_TRUE(copied.HasSubscribers(eventId));
    EXPECT_FALSE(snapshot.HasSubscribers(eventId));
    EXPECT_FALSE(copied.HasSubscribers(1));
    EXPECT_EQ(copied.version, 19u);
}
} // namespace OHOS::DistributedData
