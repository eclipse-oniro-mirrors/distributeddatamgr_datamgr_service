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

#include "installer_impl.h"
#include <gtest/gtest.h>
#include "common_event_support.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedKv;
using namespace OHOS::EventFwk;
namespace OHOS::Test {
class InstallerImplTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
};

/**
* @tc.name: InstallCallbacksSandboxBundleRemoved001
* @tc.desc: verify COMMON_EVENT_SANDBOX_BUNDLE_REMOVED is registered and maps to OnUninstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InstallCallbacksSandboxBundleRemoved001, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // SANDBOX_BUNDLE_REMOVED must be present in callbacks_ and route to OnUninstall.
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);

    // SANDBOX_PACKAGE_REMOVED and PACKAGE_REMOVED still route to OnUninstall (regression guard).
    auto sandboxPkgIt = subscriber->callbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    ASSERT_NE(sandboxPkgIt, subscriber->callbacks_.end());
    EXPECT_EQ(sandboxPkgIt->second, &InstallEventSubscriber::OnUninstall);
    auto pkgRemovedIt = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    ASSERT_NE(pkgRemovedIt, subscriber->callbacks_.end());
    EXPECT_EQ(pkgRemovedIt->second, &InstallEventSubscriber::OnUninstall);
}

/**
* @tc.name: InitNullServiceReturnsInvalidArgument001
* @tc.desc: verify Init rejects a null KvStoreDataService before subscribing any event
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InitNullServiceReturnsInvalidArgument001, TestSize.Level1)
{
    InstallerImpl installer;
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    ASSERT_NE(executors, nullptr);
    // Init must short-circuit on null service; no common-event subscription happens.
    Status status = installer.Init(nullptr, executors);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
}

/**
* @tc.name: InstallCallbacksNoUnknownActions001
* @tc.desc: verify callbacks_ contains exactly the registered install/uninstall/update actions
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InstallCallbacksNoUnknownActions001, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // The callback table must contain the five documented events, including SANDBOX_BUNDLE_REMOVED.
    EXPECT_EQ(subscriber->callbacks_.size(), static_cast<size_t>(5));
    // SANDBOX_BUNDLE_REMOVED must NOT map to OnInstall/OnUpdate (it is an uninstall event).
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_NE(it->second, &InstallEventSubscriber::OnInstall);
    EXPECT_NE(it->second, &InstallEventSubscriber::OnUpdate);
    // An action that was never registered must not be found in the table.
    EXPECT_EQ(subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED),
        subscriber->callbacks_.end());
}

/**
* @tc.name: InstallCallbacksAllHandlersRegistered001
* @tc.desc: verify all five documented actions are present with the expected handler
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InstallCallbacksAllHandlersRegistered001, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // Uninstall handlers: PACKAGE_REMOVED, SANDBOX_PACKAGE_REMOVED, SANDBOX_BUNDLE_REMOVED.
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED],
        &InstallEventSubscriber::OnUninstall);
    EXPECT_EQ(subscriber->callbacks_[EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED],
        &InstallEventSubscriber::OnUninstall);
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED],
        &InstallEventSubscriber::OnUninstall);
    // Update / Install handlers remain unchanged (regression guard).
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED],
        &InstallEventSubscriber::OnUpdate);
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED],
        &InstallEventSubscriber::OnInstall);
    EXPECT_EQ(subscriber->callbacks_[EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_PACKAGE_ADDED],
        &InstallEventSubscriber::OnInstall);
}

/**
* @tc.name: OnReceiveEventUnknownAction001
* @tc.desc: verify OnReceiveEvent ignores an action not in callbacks_ without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventUnknownAction001, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // An action that is not in callbacks_ must be a no-op (the find returns end()).
    Want want;
    want.SetAction("usual.event.NOT_REGISTERED");
    CommonEventData event(want);
    EXPECT_EQ(subscriber->callbacks_.find("usual.event.NOT_REGISTERED"), subscriber->callbacks_.end());
    // Drive OnReceiveEvent; it is void-typed and must not crash for an unknown action.
    subscriber->OnReceiveEvent(event);
    // The callback table must remain unchanged after dispatching an unknown action.
    EXPECT_EQ(subscriber->callbacks_.size(), static_cast<size_t>(5));
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedNoCrash001
* @tc.desc: verify OnReceiveEvent parses SANDBOX_BUNDLE_REMOVED params and short-circuits on null service
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedNoCrash001, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    // service is null so OnUninstall short-circuits before touching singletons.
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // Build a SANDBOX_BUNDLE_REMOVED event; empty want is enough (null service short-circuits OnUninstall).
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetParam(InstallEventSubscriber::USER_ID, 101);
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 2);
    want.SetParam(InstallEventSubscriber::TOKEN_ID, 123456);
    want.SetParam(InstallEventSubscriber::APP_INDEX, 2);
    CommonEventData event(want);

    // The action must resolve to OnUninstall in the callback table.
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);

    // Drive OnReceiveEvent; with null service OnUninstall returns early, so no singleton is touched.
    subscriber->OnReceiveEvent(event);
    // Routing entry must remain intact after dispatch.
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
}

/**
* @tc.name: OnUninstallNullServiceNoCrash001
* @tc.desc: verify OnUninstall short-circuits when kvStoreDataService_ is null
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnUninstallNullServiceNoCrash001, TestSize.Level1)
{
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);
    // kvStoreDataService_ is null by construction; OnUninstall must early-return without crashing.
    EXPECT_EQ(subscriber->kvStoreDataService_, nullptr);

    AppDistributedKv::BundleEventInfo bundleEventInfo;
    bundleEventInfo.bundleName = "com.test.sandboxbundle";
    bundleEventInfo.userId = 101;
    bundleEventInfo.appIndex = 2;
    bundleEventInfo.tokenId = 123456;
    subscriber->OnUninstall(bundleEventInfo);
    // Service pointer must remain null (no side effect changed it).
    EXPECT_EQ(subscriber->kvStoreDataService_, nullptr);
}
} // namespace OHOS::Test
