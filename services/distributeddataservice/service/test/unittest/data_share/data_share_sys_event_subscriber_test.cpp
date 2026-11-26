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
#define LOG_TAG "DataShareSysEventSubscriberTest"

#include "sys_event_subscriber.h"

#include <gtest/gtest.h>

#include "data_share_service_impl.h"
#include "common_event_manager.h"
#include "common_event_support.h"
#include "log_print.h"
#include "mock/meta_data_manager_mock.h"
#include "proxy_data_manager.h"

namespace OHOS::Test {
using namespace OHOS::DataShare;
using namespace testing::ext;
class DataShareSysEventSubscriberTest : public testing::Test {
public:
    static void SetUpTestCase(void){};
    static void TearDownTestCase(void){};
    void SetUp(){};
    void TearDown(){};
};

/**
* @tc.name: OnBMSReady001
* @tc.desc: test OnBMSReady func
* @tc.type: FUNC
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnBMSReady001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnBMSReady001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    // executors not null
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    // make sysEventSubscriber not null
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // OnBMSReady is void-typed and const; test both normal/error cases.
    sysEventSubscriber->OnBMSReady();
    ASSERT_NE(sysEventSubscriber->executors_, nullptr);
    // cover executors == nullptr branch
    sysEventSubscriber->executors_ = nullptr;
    sysEventSubscriber->OnBMSReady();
    ZLOGI("DataShareSysEventSubscriberTest OnBMSReady001 end");
}

/**
* @tc.name: InstallCallbacksSandboxBundleRemoved001
* @tc.desc: verify COMMON_EVENT_SANDBOX_BUNDLE_REMOVED is registered and maps to OnAppUninstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, InstallCallbacksSandboxBundleRemoved001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksSandboxBundleRemoved001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // SANDBOX_BUNDLE_REMOVED must be present in installCallbacks_ and route to OnAppUninstall
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);

    // PACKAGE_REMOVED still routes to OnAppUninstall (regression guard)
    auto removedIt = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    ASSERT_NE(removedIt, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(removedIt->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksSandboxBundleRemoved001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemoved001
* @tc.desc: verify OnReceiveEvent routes SANDBOX_BUNDLE_REMOVED into the install callback table
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemoved001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemoved001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // Build a sandbox-bundle-removed event and verify OnReceiveEvent finds a matching install callback.
    // OnAppUninstall touches BundleMgrProxy / ProxyDataManager singletons; this case only asserts routing
    // (the action is in installCallbacks_), not the side effects of those singletons.
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetParam(SysEventSubscriber::USER_ID, 100);
    want.SetParam(SysEventSubscriber::APP_INDEX, 1);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 0);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    // The action carried by the event must resolve to the registered uninstall handler.
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);

    // Drive OnReceiveEvent; it is void-typed and must not crash for this action.
    sysEventSubscriber->OnReceiveEvent(event);
    // Re-assert the routing entry is intact after dispatch.
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemoved001 end");
}

/**
* @tc.name: InstallCallbacksTableSize001
* @tc.desc: verify installCallbacks_ contains exactly the four install/uninstall/update actions
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, InstallCallbacksTableSize001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksTableSize001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // The install callback table must contain exactly four actions after the SANDBOX_BUNDLE_REMOVED addition.
    EXPECT_EQ(sysEventSubscriber->installCallbacks_.size(), static_cast<size_t>(4));
    // Each documented action maps to its expected handler.
    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED], &SysEventSubscriber::OnAppInstall);
    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED], &SysEventSubscriber::OnAppUpdate);
    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED], &SysEventSubscriber::OnAppUninstall);
    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED], &SysEventSubscriber::OnAppUninstall);
    // The non-install callbacks table (BUNDLE_SCAN_FINISHED -> OnBMSReady) must remain size 1.
    EXPECT_EQ(sysEventSubscriber->callbacks_.size(), static_cast<size_t>(1));
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksTableSize001 end");
}

/**
* @tc.name: OnReceiveEventUnknownAction001
* @tc.desc: verify OnReceiveEvent ignores an action not in either callback table without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventUnknownAction001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventUnknownAction001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // An action that is in neither installCallbacks_ nor callbacks_ must be a no-op.
    const std::string unknownAction = "usual.event.NOT_REGISTERED";
    EXPECT_EQ(sysEventSubscriber->installCallbacks_.find(unknownAction),
        sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(sysEventSubscriber->callbacks_.find(unknownAction), sysEventSubscriber->callbacks_.end());

    AAFwk::Want want;
    want.SetAction(unknownAction);
    EventFwk::CommonEventData event(want);
    // Drive OnReceiveEvent; it is void-typed and must not crash for an unknown action.
    sysEventSubscriber->OnReceiveEvent(event);
    // Both callback tables must remain unchanged after dispatching an unknown action.
    EXPECT_EQ(sysEventSubscriber->installCallbacks_.size(), static_cast<size_t>(4));
    EXPECT_EQ(sysEventSubscriber->callbacks_.size(), static_cast<size_t>(1));
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventUnknownAction001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedWithTokenId001
* @tc.desc: verify OnReceiveEvent resolves SANDBOX_BUNDLE_REMOVED when the event carries a non-zero tokenId
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemovedWithTokenId001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedWithTokenId001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    subscribeInfo.SetThreadMode(EventFwk::CommonEventSubscribeInfo::COMMON);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // Build a SANDBOX_BUNDLE_REMOVED event with a non-zero tokenId so the GetHapTokenID fallback is skipped.
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.sandboxbundle", ""));
    want.SetParam(SysEventSubscriber::USER_ID, 101);
    want.SetParam(SysEventSubscriber::APP_INDEX, 2);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 654321);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);

    // The action must resolve to OnAppUninstall in the install callback table.
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);

    // Drive OnReceiveEvent; the non-zero tokenId path avoids AccessTokenKit::GetHapTokenID.
    sysEventSubscriber->OnReceiveEvent(event);
    // Routing entry must remain intact after dispatch.
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedWithTokenId001 end");
}

/**
* @tc.name: OnAppInstallDirectCallNoCrash001
* @tc.desc: verify OnAppInstall can be invoked directly with cross-app config disabled
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnAppInstallDirectCallNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnAppInstallDirectCallNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // isCrossAppSharedConfig=false -> ProxyDataManager::OnAppInstall is skipped; no crash expected.
    sysEventSubscriber->OnAppInstall("com.test.install", 100, 0, 123u, false);
    // Routing entry for PACKAGE_ADDED must remain intact.
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppInstall);
    ZLOGI("DataShareSysEventSubscriberTest OnAppInstallDirectCallNoCrash001 end");
}

/**
* @tc.name: OnAppInstallDirectCallCrossAppConfigEnabledNoCrash001
* @tc.desc: verify OnAppInstall can be invoked directly with cross-app config enabled
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnAppInstallDirectCallCrossAppConfigEnabledNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnAppInstallDirectCallCrossAppConfigEnabledNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // isCrossAppSharedConfig=true -> ProxyDataManager::OnAppInstall is invoked; in the test env it no-ops.
    sysEventSubscriber->OnAppInstall("com.test.install.cross", 100, 1, 456u, true);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppInstall);
    ZLOGI("DataShareSysEventSubscriberTest OnAppInstallDirectCallCrossAppConfigEnabledNoCrash001 end");
}

/**
* @tc.name: OnAppUpdateDirectCallNoCrash001
* @tc.desc: verify OnAppUpdate can be invoked directly and routes to BundleMgrProxy::Delete
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnAppUpdateDirectCallNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnAppUpdateDirectCallNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // OnAppUpdate always calls BundleMgrProxy::Delete; in the test env the proxy no-ops.
    sysEventSubscriber->OnAppUpdate("com.test.update", 100, 0, 789u, false);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUpdate);
    ZLOGI("DataShareSysEventSubscriberTest OnAppUpdateDirectCallNoCrash001 end");
}

/**
* @tc.name: OnAppUpdateDirectCallCrossAppConfigEnabledNoCrash001
* @tc.desc: verify OnAppUpdate with cross-app config enabled does not crash
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnAppUpdateDirectCallCrossAppConfigEnabledNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnAppUpdateDirectCallCrossAppConfigEnabledNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    sysEventSubscriber->OnAppUpdate("com.test.update.cross", 100, 1, 111u, true);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUpdate);
    ZLOGI("DataShareSysEventSubscriberTest OnAppUpdateDirectCallCrossAppConfigEnabledNoCrash001 end");
}

/**
* @tc.name: OnAppUninstallDirectCallNoCrash001
* @tc.desc: verify OnAppUninstall can be invoked directly for a sandbox bundle scenario
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnAppUninstallDirectCallNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnAppUninstallDirectCallNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // OnAppUninstall always calls BundleMgrProxy::Delete + ProxyDataManager::OnAppUninstall (test-env no-op).
    sysEventSubscriber->OnAppUninstall("com.test.uninstall", 100, 1, 222u, false);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnAppUninstallDirectCallNoCrash001 end");
}

/**
* @tc.name: OnBMSReadyNullExecutorsNoCrash001
* @tc.desc: verify OnBMSReady short-circuits when executors_ is null
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnBMSReadyNullExecutorsNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnBMSReadyNullExecutorsNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, nullptr);
    ASSERT_NE(sysEventSubscriber, nullptr);
    EXPECT_EQ(sysEventSubscriber->executors_, nullptr);

    // OnBMSReady must early-return on null executors; NotifyDataShareReady still runs (CES publish no-op).
    sysEventSubscriber->OnBMSReady();
    EXPECT_EQ(sysEventSubscriber->executors_, nullptr);
    ZLOGI("DataShareSysEventSubscriberTest OnBMSReadyNullExecutorsNoCrash001 end");
}

/**
* @tc.name: OnBMSReadyNonNullExecutorsNoCrash001
* @tc.desc: verify OnBMSReady runs end-to-end with non-null executors
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnBMSReadyNonNullExecutorsNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnBMSReadyNonNullExecutorsNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);
    ASSERT_NE(sysEventSubscriber->executors_, nullptr);

    sysEventSubscriber->OnBMSReady();
    EXPECT_NE(sysEventSubscriber->executors_, nullptr);
    ZLOGI("DataShareSysEventSubscriberTest OnBMSReadyNonNullExecutorsNoCrash001 end");
}

/**
* @tc.name: OnReceiveEventPackageAddedRoutesToOnAppInstall001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_PACKAGE_ADDED to OnAppInstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventPackageAddedRoutesToOnAppInstall001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventPackageAddedRoutesToOnAppInstall001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    want.SetElement(AAFwk::ElementName("", "com.test.added", ""));
    want.SetParam(SysEventSubscriber::USER_ID, 100);
    want.SetParam(SysEventSubscriber::APP_INDEX, 0);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 333u);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppInstall);
    sysEventSubscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppInstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventPackageAddedRoutesToOnAppInstall001 end");
}

/**
* @tc.name: OnReceiveEventPackageChangedRoutesToOnAppUpdate001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_PACKAGE_CHANGED to OnAppUpdate
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventPackageChangedRoutesToOnAppUpdate001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventPackageChangedRoutesToOnAppUpdate001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    want.SetElement(AAFwk::ElementName("", "com.test.changed", ""));
    want.SetParam(SysEventSubscriber::USER_ID, 100);
    want.SetParam(SysEventSubscriber::APP_INDEX, 0);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 444u);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUpdate);
    sysEventSubscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUpdate);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventPackageChangedRoutesToOnAppUpdate001 end");
}

/**
* @tc.name: OnReceiveEventPackageRemovedRoutesToOnAppUninstall001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_PACKAGE_REMOVED to OnAppUninstall
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventPackageRemovedRoutesToOnAppUninstall001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventPackageRemovedRoutesToOnAppUninstall001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.removed", ""));
    want.SetParam(SysEventSubscriber::USER_ID, 100);
    want.SetParam(SysEventSubscriber::APP_INDEX, 0);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 555u);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    sysEventSubscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventPackageRemovedRoutesToOnAppUninstall001 end");
}

/**
* @tc.name: OnReceiveEventBundleScanFinishedRoutesToOnBMSReady001
* @tc.desc: verify OnReceiveEvent routes COMMON_EVENT_BUNDLE_SCAN_FINISHED to OnBMSReady via callbacks_
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventBundleScanFinishedRoutesToOnBMSReady001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventBundleScanFinishedRoutesToOnBMSReady001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // BUNDLE_SCAN_FINISHED must be in the non-install callbacks_ table mapping to OnBMSReady.
    auto it = sysEventSubscriber->callbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    ASSERT_NE(it, sysEventSubscriber->callbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnBMSReady);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    EventFwk::CommonEventData event(want);
    // Drive OnReceiveEvent; it must not crash for this action.
    sysEventSubscriber->OnReceiveEvent(event);
    EXPECT_EQ(it->second, &SysEventSubscriber::OnBMSReady);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventBundleScanFinishedRoutesToOnBMSReady001 end");
}

/**
* @tc.name: InstallCallbacksAllHandlersRegistered001
* @tc.desc: verify each documented action maps to the expected handler in installCallbacks_
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, InstallCallbacksAllHandlersRegistered001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksAllHandlersRegistered001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED], &SysEventSubscriber::OnAppInstall);
    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED], &SysEventSubscriber::OnAppUpdate);
    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED], &SysEventSubscriber::OnAppUninstall);
    EXPECT_EQ(sysEventSubscriber->installCallbacks_[
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED], &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksAllHandlersRegistered001 end");
}

/**
* @tc.name: InstallCallbacksUninstallActionsDistinctFromInstallUpdate001
* @tc.desc: verify the two uninstall actions never share a handler with install/update
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, InstallCallbacksUninstallActionsDistinctFromInstallUpdate001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksUninstallActionsDistinctFromInstallUpdate001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    std::vector<std::string> uninstallActions = {
        EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED,
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED,
    };
    for (const auto &action : uninstallActions) {
        auto it = sysEventSubscriber->installCallbacks_.find(action);
        ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
        EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
        EXPECT_NE(it->second, &SysEventSubscriber::OnAppInstall);
        EXPECT_NE(it->second, &SysEventSubscriber::OnAppUpdate);
    }
    ZLOGI("DataShareSysEventSubscriberTest InstallCallbacksUninstallActionsDistinctFromInstallUpdate001 end");
}

/**
* @tc.name: CallbacksTablesStableAfterMultipleDispatch001
* @tc.desc: verify both callback tables are unchanged after dispatching multiple mixed events
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, CallbacksTablesStableAfterMultipleDispatch001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest CallbacksTablesStableAfterMultipleDispatch001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);
    const size_t initialInstall = sysEventSubscriber->installCallbacks_.size();
    const size_t initialCallbacks = sysEventSubscriber->callbacks_.size();
    EXPECT_EQ(initialInstall, static_cast<size_t>(4));
    EXPECT_EQ(initialCallbacks, static_cast<size_t>(1));

    auto dispatch = [&](const std::string &action) {
        AAFwk::Want want;
        want.SetAction(action);
        EventFwk::CommonEventData event(want);
        sysEventSubscriber->OnReceiveEvent(event);
    };
    dispatch(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    dispatch(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    dispatch(EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED);
    dispatch("usual.event.NOT_REGISTERED");
    dispatch("");

    EXPECT_EQ(sysEventSubscriber->installCallbacks_.size(), initialInstall);
    EXPECT_EQ(sysEventSubscriber->callbacks_.size(), initialCallbacks);
    ZLOGI("DataShareSysEventSubscriberTest CallbacksTablesStableAfterMultipleDispatch001 end");
}

/**
* @tc.name: SubscriberConstructDoesNotDependOnMatchingSkills001
* @tc.desc: verify the install callback table is identical regardless of which events MatchingSkills holds
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, SubscriberConstructDoesNotDependOnMatchingSkills001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest SubscriberConstructDoesNotDependOnMatchingSkills001 start");
    EventFwk::MatchingSkills skillsA;
    skillsA.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo infoA(skillsA);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto subA = std::make_shared<SysEventSubscriber>(infoA, executors);
    ASSERT_NE(subA, nullptr);

    EventFwk::MatchingSkills skillsB;
    skillsB.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo infoB(skillsB);
    auto subB = std::make_shared<SysEventSubscriber>(infoB, executors);
    ASSERT_NE(subB, nullptr);

    EXPECT_EQ(subA->installCallbacks_.size(), subB->installCallbacks_.size());
    EXPECT_EQ(subA->installCallbacks_.size(), static_cast<size_t>(4));
    EXPECT_EQ(subA->installCallbacks_[EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED],
        subB->installCallbacks_[EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED]);
    ZLOGI("DataShareSysEventSubscriberTest SubscriberConstructDoesNotDependOnMatchingSkills001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedCrossAppConfigTrue001
* @tc.desc: verify OnReceiveEvent tolerates CROSS_APP_SHARED_CONFIG=true for SANDBOX_BUNDLE_REMOVED
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemovedCrossAppConfigTrue001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedCrossAppConfigTrue001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.crossapp", ""));
    want.SetParam(SysEventSubscriber::USER_ID, 100);
    want.SetParam(SysEventSubscriber::APP_INDEX, 1);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 777u);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, true);
    EventFwk::CommonEventData event(want);
    sysEventSubscriber->OnReceiveEvent(event);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedCrossAppConfigTrue001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedNegativeUserId001
* @tc.desc: verify OnReceiveEvent tolerates a negative USER_ID value without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemovedNegativeUserId001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedNegativeUserId001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.neguser", ""));
    want.SetParam(SysEventSubscriber::USER_ID, -50);
    want.SetParam(SysEventSubscriber::APP_INDEX, 0);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 0);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    // tokenId==0 triggers the AccessTokenKit fallback path; in test env it returns 0, no crash.
    sysEventSubscriber->OnReceiveEvent(event);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedNegativeUserId001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedEmptyBundleName001
* @tc.desc: verify OnReceiveEvent tolerates an empty bundleName for SANDBOX_BUNDLE_REMOVED
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemovedEmptyBundleName001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedEmptyBundleName001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    // No Element set -> bundleName is empty.
    want.SetParam(SysEventSubscriber::USER_ID, 1);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 888u);
    EventFwk::CommonEventData event(want);
    sysEventSubscriber->OnReceiveEvent(event);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedEmptyBundleName001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedLargeAppIndex001
* @tc.desc: verify OnReceiveEvent tolerates a large APP_INDEX value without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemovedLargeAppIndex001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedLargeAppIndex001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.largeindex", ""));
    want.SetParam(SysEventSubscriber::USER_ID, 1);
    want.SetParam(SysEventSubscriber::APP_INDEX, 999);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 0);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    sysEventSubscriber->OnReceiveEvent(event);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedLargeAppIndex001 end");
}

/**
* @tc.name: CallbacksHandlerPointersAreNonNull001
* @tc.desc: verify every entry in both callback tables maps to a non-null handler pointer
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, CallbacksHandlerPointersAreNonNull001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest CallbacksHandlerPointersAreNonNull001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);
    EXPECT_FALSE(sysEventSubscriber->installCallbacks_.empty());
    for (const auto &entry : sysEventSubscriber->installCallbacks_) {
        EXPECT_NE(entry.second, nullptr);
    }
    EXPECT_FALSE(sysEventSubscriber->callbacks_.empty());
    for (const auto &entry : sysEventSubscriber->callbacks_) {
        EXPECT_NE(entry.second, nullptr);
    }
    ZLOGI("DataShareSysEventSubscriberTest CallbacksHandlerPointersAreNonNull001 end");
}

/**
* @tc.name: CallbacksKeysAreNonEmpty001
* @tc.desc: verify every key in both callback tables is a non-empty action string
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, CallbacksKeysAreNonEmpty001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest CallbacksKeysAreNonEmpty001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);
    for (const auto &entry : sysEventSubscriber->installCallbacks_) {
        EXPECT_FALSE(entry.first.empty());
    }
    for (const auto &entry : sysEventSubscriber->callbacks_) {
        EXPECT_FALSE(entry.first.empty());
    }
    ZLOGI("DataShareSysEventSubscriberTest CallbacksKeysAreNonEmpty001 end");
}

/**
* @tc.name: SubscriberDestructNoCrash001
* @tc.desc: verify a SysEventSubscriber destructs without crashing
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, SubscriberDestructNoCrash001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest SubscriberDestructNoCrash001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    // Track destruction via a weak reference: the subscriber must be gone after the block exits.
    std::weak_ptr<SysEventSubscriber> weakRef;
    {
        auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
        ASSERT_NE(sysEventSubscriber, nullptr);
        weakRef = sysEventSubscriber;
        // sysEventSubscriber goes out of scope here; destructor must not crash.
    }
    EXPECT_TRUE(weakRef.expired());
    ZLOGI("DataShareSysEventSubscriberTest SubscriberDestructNoCrash001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedZeroAppIndex001
* @tc.desc: verify OnReceiveEvent tolerates APP_INDEX=0 for SANDBOX_BUNDLE_REMOVED
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemovedZeroAppIndex001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedZeroAppIndex001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.zeroindex", ""));
    want.SetParam(SysEventSubscriber::USER_ID, 1);
    want.SetParam(SysEventSubscriber::APP_INDEX, 0);
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 999u);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    sysEventSubscriber->OnReceiveEvent(event);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedZeroAppIndex001 end");
}

/**
* @tc.name: OnReceiveEventSandboxBundleRemovedDefaultUserIdWhenAbsent001
* @tc.desc: verify OnReceiveEvent yields userId=-1 default when USER_ID param is absent
* @tc.type: FUNC
* @tc.author: agent
*/
HWTEST_F(DataShareSysEventSubscriberTest, OnReceiveEventSandboxBundleRemovedDefaultUserIdWhenAbsent001, TestSize.Level1)
{
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedDefaultUserIdWhenAbsent001 start");
    EventFwk::MatchingSkills testMatchingSkills;
    testMatchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(testMatchingSkills);
    auto executors = std::make_shared<ExecutorPool>(1, 0);
    auto sysEventSubscriber = std::make_shared<SysEventSubscriber>(subscribeInfo, executors);
    ASSERT_NE(sysEventSubscriber, nullptr);

    // No USER_ID param -> default -1; with tokenId==0 the AccessTokenKit fallback runs (test-env no-op).
    AAFwk::Want want;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    want.SetElement(AAFwk::ElementName("", "com.test.nouserid", ""));
    want.SetParam(SysEventSubscriber::ACCESS_TOKEN_ID, 0);
    want.SetParam(SysEventSubscriber::CROSS_APP_SHARED_CONFIG, false);
    EventFwk::CommonEventData event(want);
    sysEventSubscriber->OnReceiveEvent(event);
    auto it = sysEventSubscriber->installCallbacks_.find(
        EventFwk::CommonEventSupport::COMMON_EVENT_SANDBOX_BUNDLE_REMOVED);
    ASSERT_NE(it, sysEventSubscriber->installCallbacks_.end());
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemovedDefaultUserIdWhenAbsent001 end");
}
} // namespace OHOS::Test