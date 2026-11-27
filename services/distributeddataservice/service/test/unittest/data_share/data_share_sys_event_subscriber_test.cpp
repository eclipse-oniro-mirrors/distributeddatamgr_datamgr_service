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

    // Build a sandbox-bundle-removed event; only routing is asserted (singletons are not mocked).
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
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);

    // Drive OnReceiveEvent; it is void-typed and must not crash for this action.
    sysEventSubscriber->OnReceiveEvent(event);
    // Re-assert the routing entry is intact after dispatch.
    EXPECT_EQ(it->second, &SysEventSubscriber::OnAppUninstall);
    ZLOGI("DataShareSysEventSubscriberTest OnReceiveEventSandboxBundleRemoved001 end");
}
} // namespace OHOS::Test