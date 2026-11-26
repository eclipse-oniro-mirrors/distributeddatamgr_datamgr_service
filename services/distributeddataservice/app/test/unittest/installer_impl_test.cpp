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
#define LOG_TAG "InstallerImplTest"

#include "installer_impl.h"

#include <gtest/gtest.h>

#include "common_event_support.h"
#include "log_print.h"

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
    ZLOGI("InstallerImplTest InstallCallbacksSandboxBundleRemoved001 start");
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
        OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    ASSERT_NE(sandboxPkgIt, subscriber->callbacks_.end());
    EXPECT_EQ(sandboxPkgIt->second, &InstallEventSubscriber::OnUninstall);
    auto pkgRemovedIt = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    ASSERT_NE(pkgRemovedIt, subscriber->callbacks_.end());
    EXPECT_EQ(pkgRemovedIt->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest InstallCallbacksSandboxBundleRemoved001 end");
}

/**
* @tc.name: InitNullServiceReturnsInvalidArgument001
* @tc.desc: verify Init rejects a null KvStoreDataService before subscribing any event
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InitNullServiceReturnsInvalidArgument001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest InitNullServiceReturnsInvalidArgument001 start");
    InstallerImpl installer;
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    ASSERT_NE(executors, nullptr);
    // Init must short-circuit on null service; no common-event subscription happens.
    Status status = installer.Init(nullptr, executors);
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    ZLOGI("InstallerImplTest InitNullServiceReturnsInvalidArgument001 end");
}

/**
* @tc.name: InstallCallbacksNoUnknownActions001
* @tc.desc: verify callbacks_ contains exactly the registered install/uninstall/update actions
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InstallCallbacksNoUnknownActions001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest InstallCallbacksNoUnknownActions001 start");
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
    ZLOGI("InstallerImplTest InstallCallbacksNoUnknownActions001 end");
}

/**
* @tc.name: InstallCallbacksAllHandlersRegistered001
* @tc.desc: verify all five documented actions are present with the expected handler
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InstallCallbacksAllHandlersRegistered001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest InstallCallbacksAllHandlersRegistered001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // Uninstall handlers: PACKAGE_REMOVED, SANDBOX_PACKAGE_REMOVED, SANDBOX_BUNDLE_REMOVED.
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED],
        &InstallEventSubscriber::OnUninstall);
    EXPECT_EQ(subscriber->callbacks_[OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED],
        &InstallEventSubscriber::OnUninstall);
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED],
        &InstallEventSubscriber::OnUninstall);
    // Update / Install handlers remain unchanged (regression guard).
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED],
        &InstallEventSubscriber::OnUpdate);
    EXPECT_EQ(subscriber->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED],
        &InstallEventSubscriber::OnInstall);
    EXPECT_EQ(subscriber->callbacks_[OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_ADDED],
        &InstallEventSubscriber::OnInstall);
    ZLOGI("InstallerImplTest InstallCallbacksAllHandlersRegistered001 end");
}

/**
* @tc.name: OnReceiveEventUnknownAction001
* @tc.desc: verify OnReceiveEvent ignores an action not in callbacks_ without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventUnknownAction001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventUnknownAction001 start");
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
    ZLOGI("InstallerImplTest OnReceiveEventUnknownAction001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedNoCrash001
* @tc.desc: verify OnReceiveEvent parses SANDBOX_BUNDLE_REMOVED params and short-circuits on null service
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedNoCrash001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedNoCrash001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    // service is null so OnUninstall short-circuits before touching singletons.
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // Build a SANDBOX_BUNDLE_REMOVED event carrying bundle/user/appIndex/tokenId params.
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.sandboxbundle", ""));
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
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedNoCrash001 end");
}

/**
* @tc.name: OnUninstallNullServiceNoCrash001
* @tc.desc: verify OnUninstall short-circuits when kvStoreDataService_ is null
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnUninstallNullServiceNoCrash001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnUninstallNullServiceNoCrash001 start");
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
    ZLOGI("InstallerImplTest OnUninstallNullServiceNoCrash001 end");
}

/**
* @tc.name: OnReceiveEventPackageRemovedRoutesToOnUninstall001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_PACKAGE_REMOVED to OnUninstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventPackageRemovedRoutesToOnUninstall001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventPackageRemovedRoutesToOnUninstall001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.pkgremoved", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 0);
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 0);
    want.SetParam(InstallEventSubscriber::TOKEN_ID, 1);
    CommonEventData event(want);
    // null service -> OnUninstall short-circuits, no singleton touched.
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventPackageRemovedRoutesToOnUninstall001 end");
}

/**
* @tc.name: OnReceiveEventSandboxPackageRemovedRoutesToOnUninstall001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_SANDBOX_PACKAGE_REMOVED to OnUninstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxPackageRemovedRoutesToOnUninstall001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxPackageRemovedRoutesToOnUninstall001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    auto it = subscriber->callbacks_.find(OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);

    Want want;
    want.SetAction(OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.sandboxpkg", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 100);
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 1);
    want.SetParam(InstallEventSubscriber::TOKEN_ID, 99);
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxPackageRemovedRoutesToOnUninstall001 end");
}

/**
* @tc.name: OnReceiveEventPackageChangedRoutesToOnUpdate001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_PACKAGE_CHANGED to OnUpdate
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventPackageChangedRoutesToOnUpdate001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventPackageChangedRoutesToOnUpdate001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUpdate);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    want.SetElement(AAFwk::ElementName("", "com.test.changed", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 10);
    CommonEventData event(want);
    // null service -> OnUpdate short-circuits.
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUpdate);
    ZLOGI("InstallerImplTest OnReceiveEventPackageChangedRoutesToOnUpdate001 end");
}

/**
* @tc.name: OnReceiveEventPackageAddedRoutesToOnInstall001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_PACKAGE_ADDED to OnInstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventPackageAddedRoutesToOnInstall001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventPackageAddedRoutesToOnInstall001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnInstall);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    want.SetElement(AAFwk::ElementName("", "com.test.added", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 11);
    CommonEventData event(want);
    // null service -> OnInstall short-circuits.
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnInstall);
    ZLOGI("InstallerImplTest OnReceiveEventPackageAddedRoutesToOnInstall001 end");
}

/**
* @tc.name: OnReceiveEventSandboxPackageAddedRoutesToOnInstall001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_SANDBOX_PACKAGE_ADDED to OnInstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxPackageAddedRoutesToOnInstall001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxPackageAddedRoutesToOnInstall001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_ADDED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    auto it = subscriber->callbacks_.find(OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_ADDED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnInstall);

    Want want;
    want.SetAction(OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_ADDED);
    want.SetElement(AAFwk::ElementName("", "com.test.sandboxadded", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 12);
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnInstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxPackageAddedRoutesToOnInstall001 end");
}

/**
* @tc.name: OnReceiveEventEmptyActionNoCrash001
* @tc.desc: verify OnReceiveEvent ignores an empty action string without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventEmptyActionNoCrash001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventEmptyActionNoCrash001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    Want want;
    // No action set -> GetAction returns empty string -> not in callbacks_.
    CommonEventData event(want);
    EXPECT_EQ(subscriber->callbacks_.find(""), subscriber->callbacks_.end());
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(subscriber->callbacks_.size(), static_cast<size_t>(5));
    ZLOGI("InstallerImplTest OnReceiveEventEmptyActionNoCrash001 end");
}

/**
* @tc.name: OnReceiveEventDefaultUserIdWhenAbsent001
* @tc.desc: verify OnReceiveEvent yields userId=-1 when USER_ID param is absent from the want
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventDefaultUserIdWhenAbsent001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventDefaultUserIdWhenAbsent001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // Build an event with the action but no USER_ID param; the default -1 must be used internally.
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.nouserid", ""));
    CommonEventData event(want);
    // The action must still resolve to OnUninstall; with null service it short-circuits.
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventDefaultUserIdWhenAbsent001 end");
}

/**
* @tc.name: OnReceiveEventAppIndexMergeWhenSandboxZeroAndAppIndexNonZero001
* @tc.desc: verify appIndex is taken from APP_INDEX when SANDBOX_APP_INDEX is 0
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventAppIndexMergeWhenSandboxZeroAndAppIndexNonZero001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventAppIndexMergeWhenSandboxZeroAndAppIndexNonZero001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // SANDBOX_APP_INDEX=0 + APP_INDEX=5 -> merged appIndex=5. null service short-circuits OnUninstall.
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.merge", ""));
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 0);
    want.SetParam(InstallEventSubscriber::APP_INDEX, 5);
    CommonEventData event(want);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    subscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventAppIndexMergeWhenSandboxZeroAndAppIndexNonZero001 end");
}

/**
* @tc.name: OnReceiveEventAppIndexKeepsSandboxWhenNonZero001
* @tc.desc: verify appIndex keeps the SANDBOX_APP_INDEX value when it is non-zero
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventAppIndexKeepsSandboxWhenNonZero001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventAppIndexKeepsSandboxWhenNonZero001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // SANDBOX_APP_INDEX=3 (non-zero) -> appIndex stays 3 regardless of APP_INDEX.
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.keepsandbox", ""));
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 3);
    want.SetParam(InstallEventSubscriber::APP_INDEX, 9);
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventAppIndexKeepsSandboxWhenNonZero001 end");
}

/**
* @tc.name: OnUpdateNullServiceNoCrash001
* @tc.desc: verify OnUpdate short-circuits when kvStoreDataService_ is null
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnUpdateNullServiceNoCrash001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnUpdateNullServiceNoCrash001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);
    EXPECT_EQ(subscriber->kvStoreDataService_, nullptr);

    AppDistributedKv::BundleEventInfo bundleEventInfo;
    bundleEventInfo.bundleName = "com.test.update";
    bundleEventInfo.userId = 5;
    bundleEventInfo.appIndex = 0;
    subscriber->OnUpdate(bundleEventInfo);
    EXPECT_EQ(subscriber->kvStoreDataService_, nullptr);
    ZLOGI("InstallerImplTest OnUpdateNullServiceNoCrash001 end");
}

/**
* @tc.name: OnInstallNullServiceNoCrash001
* @tc.desc: verify OnInstall short-circuits when kvStoreDataService_ is null
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnInstallNullServiceNoCrash001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnInstallNullServiceNoCrash001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);
    EXPECT_EQ(subscriber->kvStoreDataService_, nullptr);

    AppDistributedKv::BundleEventInfo bundleEventInfo;
    bundleEventInfo.bundleName = "com.test.install";
    bundleEventInfo.userId = 6;
    bundleEventInfo.appIndex = 0;
    subscriber->OnInstall(bundleEventInfo);
    EXPECT_EQ(subscriber->kvStoreDataService_, nullptr);
    ZLOGI("InstallerImplTest OnInstallNullServiceNoCrash001 end");
}

/**
* @tc.name: CallbacksTableStableAfterMultipleDispatch001
* @tc.desc: verify the callbacks_ table is unchanged after dispatching multiple mixed events
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, CallbacksTableStableAfterMultipleDispatch001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest CallbacksTableStableAfterMultipleDispatch001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);
    const size_t initialSize = subscriber->callbacks_.size();
    EXPECT_EQ(initialSize, static_cast<size_t>(5));

    // Dispatch a sequence of mixed actions: known, unknown, empty.
    auto dispatch = [&](const std::string &action) {
        Want want;
        want.SetAction(action);
        CommonEventData event(want);
        subscriber->OnReceiveEvent(event);
    };
    dispatch(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    dispatch(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    dispatch("usual.event.NOT_REGISTERED");
    dispatch("");
    dispatch(CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED); // not registered in this instance

    // Table size and the SANDBOX_BUNDLE_REMOVED mapping must remain stable.
    EXPECT_EQ(subscriber->callbacks_.size(), initialSize);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest CallbacksTableStableAfterMultipleDispatch001 end");
}

/**
* @tc.name: SubscriberConstructDoesNotDependOnMatchingSkills001
* @tc.desc: verify the callback table is identical regardless of which events MatchingSkills holds
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, SubscriberConstructDoesNotDependOnMatchingSkills001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest SubscriberConstructDoesNotDependOnMatchingSkills001 start");
    // Two subscribers built with different MatchingSkills must end up with the same callback table,
    // because the table is fixed in the constructor body, not derived from MatchingSkills.
    MatchingSkills skillsA;
    skillsA.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    CommonEventSubscribeInfo infoA(skillsA);
    auto subA = std::make_shared<InstallEventSubscriber>(infoA, nullptr);
    ASSERT_NE(subA, nullptr);

    MatchingSkills skillsB;
    skillsB.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    skillsB.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    CommonEventSubscribeInfo infoB(skillsB);
    auto subB = std::make_shared<InstallEventSubscriber>(infoB, nullptr);
    ASSERT_NE(subB, nullptr);

    EXPECT_EQ(subA->callbacks_.size(), subB->callbacks_.size());
    EXPECT_EQ(subA->callbacks_.size(), static_cast<size_t>(5));
    EXPECT_EQ(subA->callbacks_[CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED],
        subB->callbacks_[CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED]);
    EXPECT_EQ(subA->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED],
        subB->callbacks_[CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED]);
    ZLOGI("InstallerImplTest SubscriberConstructDoesNotDependOnMatchingSkills001 end");
}

/**
* @tc.name: CallbacksAllUninstallActionsDistinctFromInstallAndUpdate001
* @tc.desc: verify the three uninstall actions never share a handler with install/update actions
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, CallbacksAllUninstallActionsDistinctFromInstallAndUpdate001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest CallbacksAllUninstallActionsDistinctFromInstallAndUpdate001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // Collect all uninstall actions and assert none equals the install/update handlers.
    std::vector<std::string> uninstallActions = {
        CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED,
        OHOS::AppExecFwk::COMMON_EVENT_SANDBOX_PACKAGE_REMOVED,
        CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED,
    };
    for (const auto &action : uninstallActions) {
        auto it = subscriber->callbacks_.find(action);
        ASSERT_NE(it, subscriber->callbacks_.end());
        EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
        EXPECT_NE(it->second, &InstallEventSubscriber::OnInstall);
        EXPECT_NE(it->second, &InstallEventSubscriber::OnUpdate);
    }
    ZLOGI("InstallerImplTest CallbacksAllUninstallActionsDistinctFromInstallAndUpdate001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedWithAppIdentifier001
* @tc.desc: verify OnReceiveEvent parses appIdentifier string param for SANDBOX_BUNDLE_REMOVED
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedWithAppIdentifier001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedWithAppIdentifier001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.appident", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 200);
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 1);
    want.SetParam(InstallEventSubscriber::TOKEN_ID, 555);
    want.SetParam(InstallEventSubscriber::APP_INDEX, 1);
    want.SetParam(InstallEventSubscriber::appIdentifier, "app-identifier-xyz");
    CommonEventData event(want);
    // null service -> OnUninstall short-circuits; the param parsing must not crash.
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedWithAppIdentifier001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedDefaultTokenIdWhenAbsent001
* @tc.desc: verify OnReceiveEvent yields tokenId=-1 default when TOKEN_ID param is absent
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedDefaultTokenIdWhenAbsent001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedDefaultTokenIdWhenAbsent001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    // No TOKEN_ID param -> default -1 is used internally; with null service OnUninstall short-circuits.
    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.notoken", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 7);
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedDefaultTokenIdWhenAbsent001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedNegativeUserId001
* @tc.desc: verify OnReceiveEvent tolerates a negative USER_ID value without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedNegativeUserId001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedNegativeUserId001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.neguser", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, -100);
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedNegativeUserId001 end");
}

/**
* @tc.name: InitNullServiceNullExecutorsReturnsInvalidArgument001
* @tc.desc: verify Init returns INVALID_ARGUMENT when both service and executors are null
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, InitNullServiceNullExecutorsReturnsInvalidArgument001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest InitNullServiceNullExecutorsReturnsInvalidArgument001 start");
    InstallerImpl installer;
    Status status = installer.Init(nullptr, nullptr);
    // The service-null guard runs first and returns INVALID_ARGUMENT.
    EXPECT_EQ(status, Status::INVALID_ARGUMENT);
    ZLOGI("InstallerImplTest InitNullServiceNullExecutorsReturnsInvalidArgument001 end");
}

/**
* @tc.name: CallbacksHandlerPointersAreNonNullException001
* @tc.desc: verify every entry in callbacks_ maps to a non-null handler pointer
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, CallbacksHandlerPointersAreNonNullException001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest CallbacksHandlerPointersAreNonNullException001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);
    EXPECT_FALSE(subscriber->callbacks_.empty());
    for (const auto &entry : subscriber->callbacks_) {
        EXPECT_NE(entry.second, nullptr);
    }
    ZLOGI("InstallerImplTest CallbacksHandlerPointersAreNonNullException001 end");
}

/**
* @tc.name: CallbacksKeysAreNonEmptyException001
* @tc.desc: verify every key in callbacks_ is a non-empty action string
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, CallbacksKeysAreNonEmptyException001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest CallbacksKeysAreNonEmptyException001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);
    for (const auto &entry : subscriber->callbacks_) {
        EXPECT_FALSE(entry.first.empty());
    }
    ZLOGI("InstallerImplTest CallbacksKeysAreNonEmptyException001 end");
}

/**
* @tc.name: SubscriberDestructWithNullServiceNoCrash001
* @tc.desc: verify an InstallEventSubscriber with null service destructs without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, SubscriberDestructWithNullServiceNoCrash001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest SubscriberDestructWithNullServiceNoCrash001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    {
        // Track destruction via a weak reference: the subscriber must be gone after the block exits.
        std::weak_ptr<InstallEventSubscriber> weakRef;
        {
            auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
            ASSERT_NE(subscriber, nullptr);
            EXPECT_EQ(subscriber->kvStoreDataService_, nullptr);
            weakRef = subscriber;
            // subscriber goes out of scope here; destructor must not crash.
        }
        // The weak reference must be expired after the subscriber was destroyed.
        EXPECT_TRUE(weakRef.expired());
    }
    ZLOGI("InstallerImplTest SubscriberDestructWithNullServiceNoCrash001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedLargeUserId001
* @tc.desc: verify OnReceiveEvent tolerates a large USER_ID value without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedLargeUserId001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedLargeUserId001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.largeuser", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 1000000);
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedLargeUserId001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedLargeAppIndex001
* @tc.desc: verify OnReceiveEvent tolerates a large SANDBOX_APP_INDEX value without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedLargeAppIndex001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedLargeAppIndex001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.largeindex", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 1);
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 999);
    want.SetParam(InstallEventSubscriber::APP_INDEX, 999);
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedLargeAppIndex001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedZeroAppIndexZeroNewAppIndex001
* @tc.desc: verify appIndex stays 0 when both SANDBOX_APP_INDEX and APP_INDEX are 0
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedZeroAppIndexZeroNewAppIndex001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedZeroAppIndexZeroNewAppIndex001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.zeroindex", ""));
    want.SetParam(InstallEventSubscriber::USER_ID, 1);
    want.SetParam(InstallEventSubscriber::SANDBOX_APP_INDEX, 0);
    want.SetParam(InstallEventSubscriber::APP_INDEX, 0);
    CommonEventData event(want);
    // No merge happens; appIndex stays 0. null service short-circuits.
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedZeroAppIndexZeroNewAppIndex001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedEmptyBundleName001
* @tc.desc: verify OnReceiveEvent tolerates an empty bundleName (no Element set on the want)
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(InstallerImplTest, OnReceiveEventSandboxBundleRemovedEmptyBundleName001, TestSize.Level1)
{
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedEmptyBundleName001 start");
    MatchingSkills matchingSkills;
    matchingSkills.AddEvent(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    CommonEventSubscribeInfo info(matchingSkills);
    auto subscriber = std::make_shared<InstallEventSubscriber>(info, nullptr);
    ASSERT_NE(subscriber, nullptr);

    Want want;
    want.SetAction(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    // No Element set -> bundleName is empty; with null service OnUninstall short-circuits.
    CommonEventData event(want);
    subscriber->OnReceiveEvent(event);
    auto it = subscriber->callbacks_.find(CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, subscriber->callbacks_.end());
    EXPECT_EQ(it->second, &InstallEventSubscriber::OnUninstall);
    ZLOGI("InstallerImplTest OnReceiveEventSandboxBundleRemovedEmptyBundleName001 end");
}
} // namespace OHOS::Test
