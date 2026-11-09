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

#include "security_guard_delegate_default_impl.h"

#include <gtest/gtest.h>

#include "security_guard/security_guard_delegate.h"

using namespace testing::ext;
namespace OHOS {
namespace DistributedData {
class SecurityGuardDelegateDefaultTest : public testing::Test {};
/**
 * @tc.name: GetInstance_DefaultBackend_StableAndUnavailable
 * @tc.desc: Verify the registered default implementation has no SG dependency.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateDefaultTest, GetInstance_DefaultBackend_StableAndUnavailable, TestSize.Level1)
{
    auto *delegate = SecurityGuardDelegate::GetInstance();
    ASSERT_NE(delegate, nullptr);
    EXPECT_EQ(SecurityGuardDelegate::GetInstance(), delegate);
    EXPECT_TRUE(SecurityGuardDelegateDefaultImpl::Init());
    EXPECT_EQ(delegate->Start(), SecurityGuardDelegate::Status::UNAVAILABLE);
    EXPECT_FALSE(delegate->IsReady());
    auto snapshot = delegate->GetClientSnapshot();
    EXPECT_FALSE(snapshot.initialized);
    EXPECT_TRUE(snapshot.HasSubscribers(INT64_C(5000000001)));
    bool completed = false;
    EXPECT_EQ(
        delegate->Request({}, [&](auto) { completed = true; }), SecurityGuardDelegate::DispatchStatus::UNAVAILABLE);
    EXPECT_FALSE(completed);
    delegate->Stop();
    delegate->Stop();
    EXPECT_FALSE(delegate->IsReady());
}
/**
 * @tc.name: RegisterSecurityGuardInstance_NullOrDuplicate_PreservesSingleton
 * @tc.desc: Verify registration cannot replace the process-wide delegate.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateDefaultTest, RegisterSecurityGuardInstance_NullOrDuplicate_PreservesSingleton,
    TestSize.Level1)
{
    auto *original = SecurityGuardDelegate::GetInstance();
    ASSERT_NE(original, nullptr);
    SecurityGuardDelegateDefaultImpl replacement;
    EXPECT_FALSE(SecurityGuardDelegate::RegisterSecurityGuardInstance(nullptr));
    EXPECT_FALSE(SecurityGuardDelegate::RegisterSecurityGuardInstance(&replacement));
    EXPECT_EQ(SecurityGuardDelegate::GetInstance(), original);
}
/**
 * @tc.name: Request_EmptyCompletionBeforeAndAfterStop_RemainsUnavailable
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(
    SecurityGuardDelegateDefaultTest, Request_EmptyCompletionBeforeAndAfterStop_RemainsUnavailable, TestSize.Level1)
{
    SecurityGuardDelegateDefaultImpl delegate;
    EXPECT_EQ(delegate.Request({}, {}), SecurityGuardDelegate::DispatchStatus::UNAVAILABLE);
    delegate.Stop();
    EXPECT_EQ(delegate.Start(), SecurityGuardDelegate::Status::UNAVAILABLE);
    EXPECT_EQ(delegate.Request({}, {}), SecurityGuardDelegate::DispatchStatus::UNAVAILABLE);
    EXPECT_FALSE(delegate.IsReady());
}
/**
 * @tc.name: GetClientSnapshot_CallerMutation_DoesNotPersist
 * @tc.desc: Verify public behavior, failure propagation and observable state.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateDefaultTest, GetClientSnapshot_CallerMutation_DoesNotPersist, TestSize.Level1)
{
    SecurityGuardDelegateDefaultImpl delegate;
    auto snapshot = delegate.GetClientSnapshot();
    snapshot.initialized = true;
    snapshot.policies[11] = { { SecurityGuardDelegate::Strategy::DENY, 400 } };
    const auto fresh = delegate.GetClientSnapshot();
    EXPECT_FALSE(fresh.initialized);
    EXPECT_TRUE(fresh.policies.empty());
    EXPECT_EQ(fresh.version, 0u);
    bool completed = false;
    EXPECT_EQ(delegate.Request({ 11, "1.0", "{}" }, [&](auto) { completed = true; }),
        SecurityGuardDelegate::DispatchStatus::UNAVAILABLE);
    EXPECT_FALSE(completed);
}
/**
 * @tc.name: LifecycleHooks_BindAndServiceReady_KeepBackendUnavailable
 * @tc.desc: A product without SG AuthEvent cannot enable SDK dispatch through service lifecycle notifications.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(SecurityGuardDelegateDefaultTest, LifecycleHooks_BindAndServiceReady_KeepBackendUnavailable, TestSize.Level1)
{
    auto *delegate = SecurityGuardDelegate::GetInstance();
    ASSERT_NE(delegate, nullptr);
    bool dispatched = false;
    bool completed = false;
    delegate->BindTaskDispatcher([&](auto) {
        dispatched = true;
        return true;
    });
    delegate->OnServiceAvailable();
    EXPECT_EQ(delegate->Start(), SecurityGuardDelegate::Status::UNAVAILABLE);
    EXPECT_FALSE(delegate->IsReady());
    EXPECT_EQ(delegate->Request({ 0x0F810000, "1.0", "{}" }, [&](const auto &) { completed = true; }),
        SecurityGuardDelegate::DispatchStatus::UNAVAILABLE);
    delegate->OnServiceUnavailable();
    delegate->OnServiceAvailable();
    EXPECT_FALSE(delegate->IsReady());
    EXPECT_FALSE(delegate->GetClientSnapshot().initialized);
    EXPECT_FALSE(dispatched);
    EXPECT_FALSE(completed);
}

} // namespace DistributedData
} // namespace OHOS
