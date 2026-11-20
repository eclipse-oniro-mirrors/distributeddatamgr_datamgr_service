/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <cstring>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "data_fabric_address_errors.h"
#include "data_fabric_address_test_utils.h"
#include "fakes/navigation_mock.h"
#include "location_mock.h"
#include "log_print.h"
#include "message_option.h"
#include "message_parcel.h"
#include "navigation_base_data.h"
#include "navigation_common_utils.h"
#include "navigation_live_view_monitor.h"
#include "navigation_passive_location_handler.h"

#undef LOG_TAG
// The reporting scenarios log their constructed inputs and the expected branch under this tag,
// filter them on device with: hilog | grep NavigationReportScenarioTest
#define LOG_TAG "NavigationReportScenarioTest"

using namespace OHOS;
using namespace OHOS::DataFabricAddress;
using namespace NativePreferences;
using namespace testing;
using namespace testing::ext;
using OHOS::DistributedData::LogLabel;
using DataFabricAddressTest::TestDataFabricAddressCallbackStub;

namespace {
constexpr double SMALL_DISTANCE = 100.0;
constexpr double LARGE_DISTANCE = 5000.0;
constexpr double INVALID_REFERENCE_LAT = 100.0;
constexpr double INVALID_REFERENCE_LNG = 200.0;
constexpr int32_t TEST_NOTIFICATION_ID = 1024;
constexpr int64_t TEST_TIMESTAMP = 1234567;
constexpr size_t MIN_WAYPOINT_COUNT = 2;
constexpr size_t MAX_WAYPOINT_COUNT = 64;
constexpr size_t MAX_COLLECTED_WAYPOINT_COUNT = 128;
constexpr size_t TRIM_WAYPOINT_COUNT = 100;
constexpr int64_t STALE_NAVIGATION_SECONDS = 12 * 60 * 60;
constexpr size_t REPORT_MAX_SIZE = 10240;
constexpr size_t OVERSIZE_BUNDLE_NAME_LENGTH = 11000;
constexpr uint32_t UNKNOWN_TRANSACTION_CODE = 100;
const std::string TARGET_BUNDLE_NAME = "com.example.test";
const char *GEOFENCE_LIB_NAME = "libgeofence_client.z.so";
const char *SUBSCRIBE_LIVE_VIEW_SYMBOL = "CSubscribeLiveView";
const char *UNSUBSCRIBE_LIVE_VIEW_SYMBOL = "CUnsubscribeLiveView";

// Controls for the fake geofence live view dynamic library.
int32_t g_fakeSubscribeResult = 0;
int32_t g_fakeUnsubscribeResult = 0;
int32_t g_fakeSubscribeCount = 0;
int32_t g_fakeUnsubscribeCount = 0;
int32_t g_fakeDlcloseCount = 0;
bool g_fakeDlopenFail = false;
bool g_fakeDlsymFail = false;
bool g_fakeUnsubscribeSymbolMissing = false;
// The hook runs inside the fake geofence calls, it lets a test observe the monitor lock while the
// geofence service is being called.
std::function<void()> g_fakeGeofenceHook;

int32_t FakeSubscribeLiveView(const sptr<IRemoteObject> &observer)
{
    (void)observer;
    if (g_fakeGeofenceHook) {
        g_fakeGeofenceHook();
    }
    g_fakeSubscribeCount++;
    return g_fakeSubscribeResult;
}

int32_t FakeUnsubscribeLiveView()
{
    if (g_fakeGeofenceHook) {
        g_fakeGeofenceHook();
    }
    g_fakeUnsubscribeCount++;
    return g_fakeUnsubscribeResult;
}

void ResetLiveViewApiMock()
{
    g_fakeSubscribeResult = 0;
    g_fakeUnsubscribeResult = 0;
    g_fakeSubscribeCount = 0;
    g_fakeUnsubscribeCount = 0;
    g_fakeDlcloseCount = 0;
    g_fakeDlopenFail = false;
    g_fakeDlsymFail = false;
    g_fakeUnsubscribeSymbolMissing = false;
    g_fakeGeofenceHook = nullptr;
}

size_t CountOccurrences(const std::string &text, const std::string &pattern)
{
    size_t count = 0;
    size_t pos = text.find(pattern);
    while (pos != std::string::npos) {
        count++;
        pos = text.find(pattern, pos + pattern.size());
    }
    return count;
}
} // namespace

extern "C" {
void *FakeDlopen(const char *fileName, int flag)
{
    if (fileName == nullptr || std::strstr(fileName, GEOFENCE_LIB_NAME) == nullptr) {
        return nullptr;
    }
    if (g_fakeDlopenFail) {
        return nullptr;
    }
    return reinterpret_cast<void *>(1);
}

void *FakeDlsym(void *handle, const char *symbol)
{
    if (g_fakeDlsymFail) {
        return nullptr;
    }
    if (symbol != nullptr && std::strcmp(symbol, SUBSCRIBE_LIVE_VIEW_SYMBOL) == 0) {
        return reinterpret_cast<void *>(&FakeSubscribeLiveView);
    }
    if (symbol != nullptr && std::strcmp(symbol, UNSUBSCRIBE_LIVE_VIEW_SYMBOL) == 0) {
        if (g_fakeUnsubscribeSymbolMissing) {
            return nullptr;
        }
        return reinterpret_cast<void *>(&FakeUnsubscribeLiveView);
    }
    return nullptr;
}

int FakeDlclose(void *handle)
{
    if (handle != nullptr) {
        g_fakeDlcloseCount++;
        return 0;
    }
    return 0;
}
}

class DataCollectTestBase : public testing::Test {
public:
    void SetUp() override
    {
        DataFabricAddressTest::ResetNavigationCommonUtilsMock();
        DataFabricAddressTest::ResetLocationMock();
        ResetLiveViewApiMock();
        ResetLiveViewMonitor();
        ResetPassiveLocationHandler();
    }

    void TearDown() override
    {
        ResetLiveViewApiMock();
        ResetLiveViewMonitor();
        ResetPassiveLocationHandler();
    }

protected:
    static void ResetLiveViewMonitor()
    {
        auto &monitor = NavigationLiveViewMonitor::GetInstance();
        monitor.isSubscribed_.store(false);
        monitor.isUnsubscribing_.store(false);
        monitor.observer_ = nullptr;
        monitor.callback_ = nullptr;
        monitor.homePoint_ = { INVALID_REFERENCE_LAT, INVALID_REFERENCE_LNG };
        monitor.companyPoint_ = { INVALID_REFERENCE_LAT, INVALID_REFERENCE_LNG };
    }

    static void ResetPassiveLocationHandler()
    {
        auto &handler = NavigationPassiveLocationHandler::GetInstance();
        handler.isSubscribed_.store(false);
        handler.passiveCallback_ = nullptr;
        handler.ClearWaypoints();
    }

    static sptr<LiveViewObserverImpl> CreateMonitorObserver()
    {
        auto &monitor = NavigationLiveViewMonitor::GetInstance();
        monitor.observer_ = sptr<LiveViewObserverImpl>(new LiveViewObserverImpl());
        return monitor.observer_;
    }

    static void StartNavigation()
    {
        auto &monitor = NavigationLiveViewMonitor::GetInstance();
        if (monitor.observer_ == nullptr) {
            monitor.observer_ = sptr<LiveViewObserverImpl>(new LiveViewObserverImpl());
        }
        monitor.observer_->OnLiveViewChanged(
            MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    }

    static bool HasActiveNavigation()
    {
        return NavigationLiveViewMonitor::GetInstance().HasActiveNavigation();
    }

    static int32_t SubscribeMonitor(const sptr<TestDataFabricAddressCallbackStub> &callback)
    {
        return NavigationLiveViewMonitor::GetInstance().SubscribeNavigationLiveView(
            MakeHomePoint(), MakeCompanyPoint(), callback);
    }

    static sptr<TestDataFabricAddressCallbackStub> MakeCallbackStub()
    {
        return sptr<TestDataFabricAddressCallbackStub>(new TestDataFabricAddressCallbackStub());
    }

    static LocationPoint MakeHomePoint()
    {
        return { 31.2304, 121.4737 };
    }

    static LocationPoint MakeCompanyPoint()
    {
        return { 31.2204, 121.4137 };
    }

    static LiveViewEvent MakeLiveViewEvent(LiveViewEventType eventType, const std::string &bundleName)
    {
        LiveViewEvent event;
        event.eventType = eventType;
        event.bundleName = bundleName;
        event.notificationId = TEST_NOTIFICATION_ID;
        event.timestamp = TEST_TIMESTAMP;
        return event;
    }

    static void AddTestWaypoints(size_t count)
    {
        auto &handler = NavigationPassiveLocationHandler::GetInstance();
        for (size_t i = 0; i < count; i++) {
            handler.AddWaypoints({ static_cast<int64_t>(i), static_cast<double>(i), static_cast<double>(i) });
        }
    }

    static size_t GetWaypointCount()
    {
        std::vector<Waypoint> waypoints;
        NavigationPassiveLocationHandler::GetInstance().ReadWaypoints(waypoints);
        return waypoints.size();
    }

    static void WriteLiveViewEvent(MessageParcel &data, int32_t eventType, const std::string &bundleName)
    {
        data.WriteInt32(eventType);
        data.WriteString(bundleName);
        data.WriteInt32(TEST_NOTIFICATION_ID);
        data.WriteInt64(TEST_TIMESTAMP);
    }

    // Logs the scenario inputs before it runs, so that a run of the report scenarios can be
    // followed on device and a failure can be told apart from a wrong scenario construction.
    static void LogReportScenario(const std::string &caseTag, const std::string &setup, const std::string &expect)
    {
        ZLOGI("[ConstructReportResult][Case%{public}s] setup={%{public}s} expect={%{public}s}",
            caseTag.c_str(), setup.c_str(), expect.c_str());
    }

    // Logs the branch counters and the remaining waypoints actually observed, so that a scenario run
    // shows on device which branch was taken even when it passes.
    static void LogReportObservedResult(const std::string &caseTag, const std::string &reportCode)
    {
        ZLOGI("[ConstructReportResult][Case%{public}s] observed={reportCode=%{public}s, "
            "isDistanceLessThanCalls=%{public}d, lastDistanceThreshold=%{public}f, getDistanceCalls=%{public}d, "
            "waypointsLeft=%{public}zu}", caseTag.c_str(), reportCode.c_str(),
            DataFabricAddressTest::GetIsDistanceLessThanCallCount(),
            DataFabricAddressTest::GetLastDistanceThreshold(),
            DataFabricAddressTest::GetGetDistanceCallCount(), GetWaypointCount());
    }

    // Injects the monitor state that the reporting flow needs: an observer to receive the start/end
    // events, the report callback and the subscribed flag. The geofence notification is deliberately
    // not subscribed, so these scenarios can run in an environment where the geofence repository is
    // absent.
    static void PrepareReportScenario(const sptr<TestDataFabricAddressCallbackStub> &callback)
    {
        auto &monitor = NavigationLiveViewMonitor::GetInstance();
        monitor.observer_ = sptr<LiveViewObserverImpl>(new LiveViewObserverImpl());
        monitor.callback_ = callback;
        monitor.isSubscribed_.store(true);
        monitor.UpdateReferenceLocation(MakeHomePoint(), MakeCompanyPoint());
    }

    // Sends a start/end event of the target navigation app to the observer of the monitor.
    static bool SendLiveViewEvent(LiveViewEventType eventType)
    {
        auto &monitor = NavigationLiveViewMonitor::GetInstance();
        if (monitor.observer_ == nullptr) {
            return false;
        }
        monitor.observer_->OnLiveViewChanged(MakeLiveViewEvent(eventType, TARGET_BUNDLE_NAME));
        return true;
    }

    // Reports locations the way the location service does: every point goes through the passive
    // locating callback and is collected or dropped by the production distance filter.
    static void ReportLocationPoints(size_t count)
    {
        PassiveLocatingCallback callback;
        for (size_t i = 0; i < count; i++) {
            const double coordinate = static_cast<double>(i);
            callback.OnLocationReport(std::make_unique<Location::Location>(coordinate, coordinate));
        }
    }
};

class NavigationLiveViewMonitorTest : public DataCollectTestBase {};

/*
 * NOTE: the dynamic loader failure cases below must stay ahead of the first
 * successful subscription of this test binary. The geofence handle is cached
 * inside the production code once it is loaded successfully, so the dlopen and
 * dlsym failure branches can only be reached before any successful load.
 */

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_DlopenFailed_ReturnsInternalException
 * @tc.desc: Test SubscribeNavigationLiveView fails when the geofence client library cannot be loaded.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_DlopenFailed_ReturnsInternalException, TestSize.Level0)
{
    g_fakeDlopenFail = true;
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    int32_t result = NavigationLiveViewMonitor::GetInstance().SubscribeNavigationLiveView(
        MakeHomePoint(), MakeCompanyPoint(), callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    EXPECT_FALSE(monitor.isSubscribed_.load());
    EXPECT_TRUE(monitor.observer_ == nullptr);
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_UnsubscribeSymbolMissing_ReturnsInternalException
 * @tc.desc: Test SubscribeNavigationLiveView fails when only the unsubscribe api cannot be resolved.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_UnsubscribeSymbolMissing_ReturnsInternalException,
    TestSize.Level0)
{
    g_fakeUnsubscribeSymbolMissing = true;
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    int32_t result = monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(monitor.isSubscribed_.load());
    EXPECT_TRUE(monitor.observer_ == nullptr);
    EXPECT_EQ(g_fakeSubscribeCount, 0);
    EXPECT_EQ(g_fakeDlcloseCount, 1);
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_DlsymFailed_ReturnsInternalException
 * @tc.desc: Test SubscribeNavigationLiveView fails and releases the library when the live view api cannot be
 * resolved, and the library is loaded again on the next subscription.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_DlsymFailed_ReturnsInternalException, TestSize.Level0)
{
    g_fakeDlsymFail = true;
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    int32_t result = monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(monitor.isSubscribed_.load());
    EXPECT_TRUE(monitor.observer_ == nullptr);
    EXPECT_EQ(g_fakeSubscribeCount, 0);
    EXPECT_EQ(g_fakeDlcloseCount, 1);

    // The handle is released after the failed load, so the next subscription loads the library again.
    g_fakeDlsymFail = false;
    EXPECT_EQ(SubscribeMonitor(callback), RUN_OK);
    EXPECT_EQ(g_fakeSubscribeCount, 1);
    EXPECT_TRUE(monitor.isSubscribed_.load());
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_ValidInput_SubscribeSuccess
 * @tc.desc: Test SubscribeNavigationLiveView succeeds and caches the reference points and callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_ValidInput_SubscribeSuccess, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    LocationPoint homePoint = MakeHomePoint();
    LocationPoint companyPoint = MakeCompanyPoint();
    int32_t result = NavigationLiveViewMonitor::GetInstance().SubscribeNavigationLiveView(
        homePoint, companyPoint, callback);
    EXPECT_EQ(result, RUN_OK);
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    EXPECT_TRUE(monitor.isSubscribed_.load());
    EXPECT_TRUE(monitor.observer_ != nullptr);
    EXPECT_TRUE(monitor.callback_.GetRefPtr() == callback.GetRefPtr());
    EXPECT_EQ(monitor.GetHomePoint().latitude, homePoint.latitude);
    EXPECT_EQ(monitor.GetCompanyPoint().longitude, companyPoint.longitude);
    EXPECT_EQ(g_fakeSubscribeCount, 1);
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_SubscribeApiFailed_ReturnsInternalException
 * @tc.desc: Test SubscribeNavigationLiveView fails when the geofence live view subscription fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_SubscribeApiFailed_ReturnsInternalException, TestSize.Level0)
{
    g_fakeSubscribeResult = -1;
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    int32_t result = monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(monitor.isSubscribed_.load());
    EXPECT_TRUE(monitor.observer_ == nullptr);
    EXPECT_EQ(g_fakeSubscribeCount, 1);
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_AlreadySubscribed_ReturnsOk
 * @tc.desc: Test SubscribeNavigationLiveView is idempotent when the monitor has been subscribed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_AlreadySubscribed_ReturnsOk, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback), RUN_OK);
    int32_t result = monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback);
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(g_fakeSubscribeCount, 1);
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_AlreadySubscribed_RefreshSubscriber
 * @tc.desc: Test a repeated subscription refreshes the reference points and the callback of an already
 *           subscribed monitor without subscribing the geofence live view again.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_AlreadySubscribed_RefreshSubscriber, TestSize.Level0)
{
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(SubscribeMonitor(MakeCallbackStub()), RUN_OK);
    sptr<TestDataFabricAddressCallbackStub> secondCallback = MakeCallbackStub();
    LocationPoint homePoint = { 32.0, 122.0 };
    LocationPoint companyPoint = { 32.5, 122.5 };

    int32_t result = monitor.SubscribeNavigationLiveView(homePoint, companyPoint, secondCallback);

    EXPECT_EQ(result, RUN_OK);
    // The previous subscriber may have died, the new one takes over the reports without subscribing the
    // geofence live view again.
    EXPECT_TRUE(monitor.callback_.GetRefPtr() == secondCallback.GetRefPtr());
    EXPECT_EQ(monitor.GetHomePoint().latitude, homePoint.latitude);
    EXPECT_EQ(monitor.GetCompanyPoint().longitude, companyPoint.longitude);
    EXPECT_EQ(g_fakeSubscribeCount, 1);
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_NullCallback_ReturnsInternalException
 * @tc.desc: Test SubscribeNavigationLiveView fails when the callback is null.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_NullCallback_ReturnsInternalException, TestSize.Level0)
{
    int32_t result = NavigationLiveViewMonitor::GetInstance().SubscribeNavigationLiveView(
        MakeHomePoint(), MakeCompanyPoint(), nullptr);
    EXPECT_EQ(result, INTERNAL_EXCEPTION);
    EXPECT_FALSE(NavigationLiveViewMonitor::GetInstance().isSubscribed_.load());
}

/**
 * @tc.name: NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_NotSubscribed_ReturnsOk
 * @tc.desc: Test UnsubscribeNavigationLiveView returns ok when the monitor has not been subscribed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_NotSubscribed_ReturnsOk, TestSize.Level0)
{
    int32_t result = NavigationLiveViewMonitor::GetInstance().UnsubscribeNavigationLiveView();
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(g_fakeUnsubscribeCount, 0);
}

/**
 * @tc.name: NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_NullObserver_ResetState
 * @tc.desc: Test UnsubscribeNavigationLiveView returns ok when the observer has been released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_NullObserver_ResetState, TestSize.Level0)
{
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    monitor.isSubscribed_.store(true);
    monitor.observer_ = nullptr;
    int32_t result = monitor.UnsubscribeNavigationLiveView();
    EXPECT_EQ(result, RUN_OK);
    EXPECT_FALSE(monitor.isSubscribed_.load());
    EXPECT_EQ(g_fakeUnsubscribeCount, 0);
}

/**
 * @tc.name: NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_Subscribed_ResetState
 * @tc.desc: Test UnsubscribeNavigationLiveView clears the cached state when the observer is unsubscribed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_Subscribed_ResetState, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback), RUN_OK);
    int32_t result = monitor.UnsubscribeNavigationLiveView();
    EXPECT_EQ(result, RUN_OK);
    EXPECT_FALSE(monitor.isSubscribed_.load());
    EXPECT_TRUE(monitor.observer_ == nullptr);
    EXPECT_TRUE(monitor.callback_ == nullptr);
    EXPECT_EQ(monitor.GetHomePoint().latitude, INVALID_REFERENCE_LAT);
    EXPECT_EQ(monitor.GetCompanyPoint().latitude, INVALID_REFERENCE_LAT);
    EXPECT_EQ(monitor.GetHomePoint().longitude, INVALID_REFERENCE_LNG);
    EXPECT_EQ(monitor.GetCompanyPoint().longitude, INVALID_REFERENCE_LNG);
    EXPECT_EQ(g_fakeUnsubscribeCount, 1);
}

/**
 * @tc.name: NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_UnsubscribeFailed_KeepState
 * @tc.desc: Test UnsubscribeNavigationLiveView keeps the state when the live view unsubscription fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_UnsubscribeFailed_KeepState, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback), RUN_OK);
    g_fakeUnsubscribeResult = -1;
    int32_t result = monitor.UnsubscribeNavigationLiveView();
    EXPECT_EQ(result, -1);
    EXPECT_TRUE(monitor.isSubscribed_.load());
    EXPECT_TRUE(monitor.observer_ != nullptr);
    EXPECT_EQ(g_fakeUnsubscribeCount, 1);
    EXPECT_FALSE(monitor.isUnsubscribing_.load());
    // The reports resume after the failed unsubscription.
    monitor.ReportNavigationData(StatusCode::SUCCESS, "resume result");
    EXPECT_EQ(callback->callCount, 1);
}

/**
 * @tc.name: NavigationLiveViewMonitor_SubscribeNavigationLiveView_GeofenceInFlight_MonitorLockNotHeld
 * @tc.desc: Test the geofence subscription is called while the monitor lock is not held and the state is installed
 * only after the subscription returns.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_SubscribeNavigationLiveView_GeofenceInFlight_MonitorLockNotHeld, TestSize.Level0)
{
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    bool lockAcquired = false;
    bool stateIsNotSubscribed = false;
    g_fakeGeofenceHook = [&monitor, &lockAcquired, &stateIsNotSubscribed]() {
        if (!monitor.mutex_.try_lock()) {
            return;
        }
        lockAcquired = true;
        stateIsNotSubscribed = !monitor.isSubscribed_.load();
        monitor.mutex_.unlock();
    };
    int32_t result = monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), MakeCallbackStub());
    EXPECT_EQ(result, RUN_OK);
    EXPECT_EQ(g_fakeSubscribeCount, 1);
    EXPECT_TRUE(lockAcquired);
    EXPECT_TRUE(stateIsNotSubscribed);
    EXPECT_TRUE(monitor.isSubscribed_.load());
}

/**
 * @tc.name: NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_GeofenceInFlight_MonitorLockNotHeld
 * @tc.desc: Test the geofence unsubscription is called while the monitor lock is not held and the state is kept
 * until it returns.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_GeofenceInFlight_MonitorLockNotHeld, TestSize.Level0)
{
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(SubscribeMonitor(MakeCallbackStub()), RUN_OK);
    bool lockAcquired = false;
    bool stateIsSubscribed = false;
    bool stateIsUnsubscribing = false;
    g_fakeGeofenceHook = [&monitor, &lockAcquired, &stateIsSubscribed, &stateIsUnsubscribing]() {
        if (!monitor.mutex_.try_lock()) {
            return;
        }
        lockAcquired = true;
        stateIsSubscribed = monitor.isSubscribed_.load() && monitor.observer_ != nullptr;
        stateIsUnsubscribing = monitor.isUnsubscribing_.load();
        monitor.mutex_.unlock();
    };
    EXPECT_EQ(monitor.UnsubscribeNavigationLiveView(), RUN_OK);
    EXPECT_EQ(g_fakeUnsubscribeCount, 1);
    EXPECT_TRUE(lockAcquired);
    EXPECT_TRUE(stateIsSubscribed);
    EXPECT_TRUE(stateIsUnsubscribing);
    EXPECT_FALSE(monitor.isSubscribed_.load());
    EXPECT_FALSE(monitor.isUnsubscribing_.load());
}

/**
 * @tc.name: NavigationLiveViewMonitor_ReportNavigationData_Unsubscribing_NoReport
 * @tc.desc: Test a report which arrives while the geofence unsubscription is in flight is dropped.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_ReportNavigationData_Unsubscribing_NoReport, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback), RUN_OK);
    int32_t reportCountDuringTeardown = -1;
    g_fakeGeofenceHook = [&monitor, &callback, &reportCountDuringTeardown]() {
        monitor.ReportNavigationData(StatusCode::SUCCESS, "teardown result");
        reportCountDuringTeardown = callback->callCount;
    };
    EXPECT_EQ(monitor.UnsubscribeNavigationLiveView(), RUN_OK);
    EXPECT_EQ(reportCountDuringTeardown, 0);
    EXPECT_EQ(callback->callCount, 0);
}

/**
 * @tc.name: NavigationLiveViewMonitor_UpdateReferenceLocation_ValidPoint_UpdateSuccess
 * @tc.desc: Test UpdateReferenceLocation refreshes the cached reference points.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_UpdateReferenceLocation_ValidPoint_UpdateSuccess, TestSize.Level0)
{
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    LocationPoint homePoint = { 30.0, 120.0 };
    LocationPoint companyPoint = { 30.1, 120.1 };
    monitor.UpdateReferenceLocation(homePoint, companyPoint);
    EXPECT_EQ(monitor.GetHomePoint().latitude, homePoint.latitude);
    EXPECT_EQ(monitor.GetHomePoint().longitude, homePoint.longitude);
    EXPECT_EQ(monitor.GetCompanyPoint().latitude, companyPoint.latitude);
    EXPECT_EQ(monitor.GetCompanyPoint().longitude, companyPoint.longitude);
}

/**
 * @tc.name: NavigationLiveViewMonitor_ReportNavigationData_NotSubscribed_NoReport
 * @tc.desc: Test ReportNavigationData does not report when the monitor has not been subscribed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_ReportNavigationData_NotSubscribed_NoReport, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    monitor.callback_ = callback;
    monitor.isSubscribed_.store(false);
    monitor.ReportNavigationData(StatusCode::SUCCESS, "result");
    EXPECT_EQ(callback->callCount, 0);
}

/**
 * @tc.name: NavigationLiveViewMonitor_ReportNavigationData_Subscribed_ReportSuccess
 * @tc.desc: Test ReportNavigationData notifies the subscribed callback.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_ReportNavigationData_Subscribed_ReportSuccess, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(monitor.SubscribeNavigationLiveView(MakeHomePoint(), MakeCompanyPoint(), callback), RUN_OK);
    monitor.ReportNavigationData(StatusCode::SUCCESS, "navigation result");
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::SUCCESS);
    EXPECT_EQ(callback->lastResult, "navigation result");
}

/**
 * @tc.name: NavigationLiveViewMonitor_ReportNavigationData_NullCallback_NoReport
 * @tc.desc: Test ReportNavigationData does not report when the cached callback is null.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_ReportNavigationData_NullCallback_NoReport, TestSize.Level0)
{
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    monitor.isSubscribed_.store(true);
    monitor.callback_ = nullptr;
    monitor.ReportNavigationData(StatusCode::SUCCESS, "ignored result");

    // The monitor keeps working after the report without callback.
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    monitor.callback_ = callback;
    monitor.ReportNavigationData(StatusCode::SUCCESS, "navigation result");
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastResult, "navigation result");
}

class NavigationLiveViewObserverTest : public DataCollectTestBase {};

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_InvalidToken_ReturnsInvalidState
 * @tc.desc: Test OnRemoteRequest returns invalid state when the interface token is not matched.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_InvalidToken_ReturnsInvalidState, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.msdp.UnknownCallback");
    int32_t result = observer.OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_UnknownCode_ReturnsUnknownTransaction
 * @tc.desc: Test OnRemoteRequest returns unknown transaction when the command code is not supported.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_UnknownCode_ReturnsUnknownTransaction, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    int32_t result = observer.OnRemoteRequest(UNKNOWN_TRANSACTION_CODE, data, reply, option);
    EXPECT_EQ(result, ERR_UNKNOWN_TRANSACTION);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_TruncatedEvent_ReturnsInvalidData
 * @tc.desc: Test OnRemoteRequest returns invalid data when the live view event is incomplete.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_TruncatedEvent_ReturnsInvalidData, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_START));
    int32_t result = observer.OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_MissingBundleName_ReturnsInvalidData
 * @tc.desc: Test OnRemoteRequest returns invalid data when the bundle name is missing.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_MissingBundleName_ReturnsInvalidData, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_START));
    int32_t result = observer.OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_MissingEventType_ReturnsInvalidData
 * @tc.desc: Test OnRemoteRequest returns invalid data when the event type is missing.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_MissingEventType_ReturnsInvalidData, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    int32_t result = observer.OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_MissingNotificationId_ReturnsInvalidData
 * @tc.desc: Test OnRemoteRequest returns invalid data when the notification id is missing.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_MissingNotificationId_ReturnsInvalidData, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_START));
    data.WriteString(TARGET_BUNDLE_NAME);
    int32_t result = observer.OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_MissingTimestamp_ReturnsInvalidData
 * @tc.desc: Test OnRemoteRequest returns invalid data when the event timestamp is missing.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_MissingTimestamp_ReturnsInvalidData, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    data.WriteInt32(static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_END));
    data.WriteString(TARGET_BUNDLE_NAME);
    data.WriteInt32(TEST_NOTIFICATION_ID);
    int32_t result = observer.OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_EventTypeBelowRange_ReturnsInvalidData
 * @tc.desc: Test OnRemoteRequest rejects an event type below the start/end range and keeps the active record.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_EventTypeBelowRange_ReturnsInvalidData, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    auto observer = NavigationLiveViewMonitor::GetInstance().observer_;
    ASSERT_TRUE(observer != nullptr);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ASSERT_TRUE(HasActiveNavigation());

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    WriteLiveViewEvent(data, static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_START) - 1, TARGET_BUNDLE_NAME);
    int32_t result = observer->OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    EXPECT_EQ(callback->callCount, 0);
    EXPECT_TRUE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_EventTypeAboveRange_ReturnsInvalidData
 * @tc.desc: Test OnRemoteRequest rejects an event type above the start/end range and keeps the active record.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_EventTypeAboveRange_ReturnsInvalidData, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    auto observer = NavigationLiveViewMonitor::GetInstance().observer_;
    ASSERT_TRUE(observer != nullptr);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ASSERT_TRUE(HasActiveNavigation());

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    WriteLiveViewEvent(data, static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_END) + 1, TARGET_BUNDLE_NAME);
    int32_t result = observer->OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    EXPECT_EQ(callback->callCount, 0);
    EXPECT_TRUE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_StartEvent_ClearWaypoints
 * @tc.desc: Test OnRemoteRequest handles a complete navigation start event.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_StartEvent_ClearWaypoints, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    ASSERT_EQ(SubscribeMonitor(callback), RUN_OK);
    AddTestWaypoints(2);
    auto observer = NavigationLiveViewMonitor::GetInstance().observer_;
    ASSERT_TRUE(observer != nullptr);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    WriteLiveViewEvent(data, static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_START), TARGET_BUNDLE_NAME);
    int32_t result = observer->OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    EXPECT_EQ(GetWaypointCount(), 0u);
    EXPECT_EQ(callback->callCount, 0);
    EXPECT_TRUE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewObserver_OnRemoteRequest_EndEvent_ReportNavigationData
 * @tc.desc: Test OnRemoteRequest handles a complete navigation end event.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnRemoteRequest_EndEvent_ReportNavigationData, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    ASSERT_EQ(SubscribeMonitor(callback), RUN_OK);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    auto observer = NavigationLiveViewMonitor::GetInstance().observer_;
    ASSERT_TRUE(observer != nullptr);
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    AddTestWaypoints(3);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(ILiveViewCallback::GetDescriptor());
    WriteLiveViewEvent(data, static_cast<int32_t>(LiveViewEventType::LIVE_VIEW_END), TARGET_BUNDLE_NAME);
    int32_t result = observer->OnRemoteRequest(ILiveViewCallback::CMD_ON_LIVE_VIEW_CHANGED,
        data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::SUCCESS);
    EXPECT_FALSE(callback->lastResult.empty());
    EXPECT_EQ(GetWaypointCount(), 0u);
    EXPECT_FALSE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_StartEvent_ClearWaypoints
 * @tc.desc: Test HandleLiveViewStart records the navigation start and clears the stale waypoints.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_StartEvent_ClearWaypoints, TestSize.Level0)
{
    AddTestWaypoints(3);
    LiveViewObserverImpl observer;
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_DuplicateStart_KeepWaypoints
 * @tc.desc: Test a duplicated navigation start event does not reset the recorded navigation.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_DuplicateStart_KeepWaypoints, TestSize.Level0)
{
    LiveViewObserverImpl observer;
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    AddTestWaypoints(2);
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    EXPECT_EQ(GetWaypointCount(), 2u);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_StaleStartRecord_ReplaceAndClearWaypoints
 * @tc.desc: Test a start event after the active record expired replaces the stale record and clears the waypoints.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_StaleStartRecord_ReplaceAndClearWaypoints, TestSize.Level0)
{
    const int64_t staleStartTimestamp = TEST_TIMESTAMP;
    const int64_t newStartTimestamp = staleStartTimestamp + STALE_NAVIGATION_SECONDS + 1;
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    DataFabricAddressTest::SetShortDistanceResult(false);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    DataFabricAddressTest::SetNowSecondTimestamp(staleStartTimestamp);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ReportLocationPoints(3);
    ASSERT_EQ(GetWaypointCount(), 3u);

    // The end event of the previous navigation is lost and the new navigation reuses the notification id.
    DataFabricAddressTest::SetNowSecondTimestamp(newStartTimestamp);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    EXPECT_TRUE(HasActiveNavigation());
    EXPECT_EQ(GetWaypointCount(), 0u);

    // The new navigation is reported with its own start timestamp and only its own waypoints.
    ReportLocationPoints(3);
    ASSERT_EQ(GetWaypointCount(), 3u);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, LARGE_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_END));
    ASSERT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::SUCCESS);
    EXPECT_NE(callback->lastResult.find("\"startTimestamp\":" + std::to_string(newStartTimestamp)),
        std::string::npos);
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_EndWithoutStart_NoReport
 * @tc.desc: Test HandleLiveViewEnd ignores the end event when no start event has been recorded.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_EndWithoutStart_NoReport, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    ASSERT_EQ(SubscribeMonitor(callback), RUN_OK);
    AddTestWaypoints(2);
    LiveViewObserverImpl observer;
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_EQ(callback->callCount, 0);
    EXPECT_EQ(GetWaypointCount(), 2u);
}

/*
 * Reporting scenarios of ConstructReportResult, run alone with:
 *   --gtest_filter=*ConstructReportResult_*
 * Each case reports locations through the passive locating callback, so the waypoint count is the
 * number of accepted reports. The geofence notification is not subscribed.
 */

/**
 * @tc.name: NavigationLiveViewObserver_ConstructReportResult_WaypointCountLessThanMinimum_ReportFailure
 * @tc.desc: Test a navigation with only one reported location ends with a failure report. An empty buffer reaches
 * the same waypoint count guard, so this case exercises the boundary just below the minimum count.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_ConstructReportResult_WaypointCountLessThanMinimum_ReportFailure, TestSize.Level0)
{
    LogReportScenario("1", "reportedLocations=1, minimumWaypointCount=" + std::to_string(MIN_WAYPOINT_COUNT),
        "report FAILURE at the waypoint count guard");
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    DataFabricAddressTest::SetShortDistanceResult(false);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ReportLocationPoints(1);
    ASSERT_EQ(GetWaypointCount(), 1u);
    // Two distance evaluations per location report: one for home, one for company.
    ASSERT_EQ(DataFabricAddressTest::GetGetDistanceCallCount(), 2);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_END));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::FAILURE);
    EXPECT_TRUE(callback->lastResult.empty());
    // The count guard returns first, the end point distance is not evaluated.
    EXPECT_EQ(DataFabricAddressTest::GetIsDistanceLessThanCallCount(), 0);
    EXPECT_EQ(DataFabricAddressTest::GetGetDistanceCallCount(), 2);
    EXPECT_EQ(GetWaypointCount(), 0u);
    LogReportObservedResult("1", "FAILURE");
}

/**
 * @tc.name: NavigationLiveViewObserver_ConstructReportResult_TripDistanceLessThanMinimum_ReportFailure
 * @tc.desc: Test HandleLiveViewEnd reports a failure and skips the reference check when the trip is shorter than
 * the minimum distance.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_ConstructReportResult_TripDistanceLessThanMinimum_ReportFailure, TestSize.Level0)
{
    const size_t reportedLocationCount = 3;
    LogReportScenario("2", "reportedLocations=" + std::to_string(reportedLocationCount) + ", tripDistance=less than " +
        std::to_string(static_cast<int32_t>(DEFAULT_MIN_NAVIGATION_TRIP_DISTANCE)) + "m",
        "report FAILURE at the trip distance guard");
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    DataFabricAddressTest::SetShortDistanceResult(true);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ReportLocationPoints(reportedLocationCount);
    ASSERT_EQ(GetWaypointCount(), reportedLocationCount);
    ASSERT_EQ(DataFabricAddressTest::GetGetDistanceCallCount(), static_cast<int32_t>(reportedLocationCount * 2));
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_END));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::FAILURE);
    // The trip distance guard is reached with the minimum threshold, the reference distance is not evaluated.
    EXPECT_EQ(DataFabricAddressTest::GetIsDistanceLessThanCallCount(), 1);
    EXPECT_DOUBLE_EQ(DataFabricAddressTest::GetLastDistanceThreshold(), DEFAULT_MIN_NAVIGATION_TRIP_DISTANCE);
    EXPECT_EQ(DataFabricAddressTest::GetGetDistanceCallCount(), static_cast<int32_t>(reportedLocationCount * 2));
    EXPECT_EQ(GetWaypointCount(), 0u);
    LogReportObservedResult("2", "FAILURE");
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_ShortTrip_KeepsReferenceCheck
 * @tc.desc: Test a trip at or above the minimum distance still reaches the home/company checks.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_ShortTrip_KeepsReferenceCheck, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    ASSERT_EQ(SubscribeMonitor(callback), RUN_OK);
    DataFabricAddressTest::SetShortDistanceResult(false);
    DataFabricAddressTest::SetGetDistanceResults(true, LARGE_DISTANCE, LARGE_DISTANCE);
    LiveViewObserverImpl observer;
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    AddTestWaypoints(3);
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::FAILURE);
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_DistanceFailed_ReportFailure
 * @tc.desc: Test HandleLiveViewEnd reports a failure when the distance cannot be calculated.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_DistanceFailed_ReportFailure, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    ASSERT_EQ(SubscribeMonitor(callback), RUN_OK);
    DataFabricAddressTest::SetGetDistanceResult(false, 0.0);
    LiveViewObserverImpl observer;
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    AddTestWaypoints(3);
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::FAILURE);
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_CompanyDistanceFailed_ReportFailure
 * @tc.desc: Test HandleLiveViewEnd reports a failure when the distance to the company cannot be calculated.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_CompanyDistanceFailed_ReportFailure, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    ASSERT_EQ(SubscribeMonitor(callback), RUN_OK);
    DataFabricAddressTest::SetGetDistanceCallResults(true, false);
    LiveViewObserverImpl observer;
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    AddTestWaypoints(3);
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::FAILURE);
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: NavigationLiveViewObserver_ConstructReportResult_EndFarFromHomeAndCompany_ReportFailure
 * @tc.desc: Test HandleLiveViewEnd reports a failure when the end point is over the maximum distance from both home
 * and company. The companion case NavigationLiveViewObserver_OnLiveViewChanged_EndNearCompany_ReportSuccess proves
 * that a single reference point within the maximum distance still passes this check.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_ConstructReportResult_EndFarFromHomeAndCompany_ReportFailure, TestSize.Level0)
{
    const size_t reportedLocationCount = 3;
    LogReportScenario("3", "reportedLocations=" + std::to_string(reportedLocationCount) + ", tripDistance=over " +
        std::to_string(static_cast<int32_t>(DEFAULT_MIN_NAVIGATION_TRIP_DISTANCE)) +
        "m, endDistanceToHome=5000m, endDistanceToCompany=5000m, maxReferenceDistance=" +
        std::to_string(static_cast<int32_t>(DEFAULT_MAX_NAVIGATION_END_DISTANCE)) + "m",
        "report FAILURE at the reference distance guard");
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    DataFabricAddressTest::SetShortDistanceResult(false);
    // The reported points are near the reference locations, otherwise the production filter drops them.
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ReportLocationPoints(reportedLocationCount);
    ASSERT_EQ(GetWaypointCount(), reportedLocationCount);
    // The user ends the trip far from both reference points.
    DataFabricAddressTest::SetGetDistanceResults(true, LARGE_DISTANCE, LARGE_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_END));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::FAILURE);
    // The trip distance guard passes and both reference points are evaluated, so the failure comes from this guard.
    EXPECT_EQ(DataFabricAddressTest::GetIsDistanceLessThanCallCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetGetDistanceCallCount(), 2);
    EXPECT_EQ(GetWaypointCount(), 0u);
    LogReportObservedResult("3", "FAILURE");
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_EndNearCompany_ReportSuccess
 * @tc.desc: Test HandleLiveViewEnd reports successfully when the end point is only near the company.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_EndNearCompany_ReportSuccess, TestSize.Level0)
{
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    ASSERT_EQ(SubscribeMonitor(callback), RUN_OK);
    DataFabricAddressTest::SetGetDistanceResults(true, LARGE_DISTANCE, SMALL_DISTANCE);
    LiveViewObserverImpl observer;
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    AddTestWaypoints(3);
    observer.OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::SUCCESS);
    EXPECT_FALSE(callback->lastResult.empty());
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: NavigationLiveViewObserver_ConstructReportResult_AllChecksPassed_ReportSuccess
 * @tc.desc: Test HandleLiveViewEnd reports a success with the built navigation result when every reporting check
 * passes.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_ConstructReportResult_AllChecksPassed_ReportSuccess, TestSize.Level0)
{
    const size_t reportedLocationCount = 4;
    LogReportScenario("6", "reportedLocations=" + std::to_string(reportedLocationCount) + ", tripDistance=over " +
        std::to_string(static_cast<int32_t>(DEFAULT_MIN_NAVIGATION_TRIP_DISTANCE)) +
        "m, endDistanceToHome=100m, endDistanceToCompany=5000m, maxReportSize=" +
        std::to_string(REPORT_MAX_SIZE), "report SUCCESS with a non-empty navigation result");
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    DataFabricAddressTest::SetShortDistanceResult(false);
    // The reported points are near the reference locations, otherwise the production filter drops them.
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ReportLocationPoints(reportedLocationCount);
    ASSERT_EQ(GetWaypointCount(), reportedLocationCount);
    // The trip ends near home and far from company, one reference point within the limit is enough.
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, LARGE_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_END));
    EXPECT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::SUCCESS);
    EXPECT_FALSE(callback->lastResult.empty());
    // The first and the last waypoints become the start and end points, the middle ones are reported.
    EXPECT_EQ(CountOccurrences(callback->lastResult, "\"timestamp\""), reportedLocationCount - 2);
    EXPECT_NE(callback->lastResult.find("\"startLatitude\":0"), std::string::npos);
    EXPECT_NE(callback->lastResult.find("\"endLatitude\":3"), std::string::npos);
    EXPECT_EQ(GetWaypointCount(), 0u);
    LogReportObservedResult("6", "SUCCESS");
}

/**
 * @tc.name: NavigationLiveViewObserver_ConstructReportResult_MiddleWaypointsExceedMaximum_TrimToLimit
 * @tc.desc: Test HandleLiveViewEnd trims the middle waypoints to the maximum count and keeps the newest ones.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_ConstructReportResult_MiddleWaypointsExceedMaximum_TrimToLimit, TestSize.Level0)
{
    const size_t reportedLocationCount = TRIM_WAYPOINT_COUNT;
    LogReportScenario("4", "reportedLocations=" + std::to_string(reportedLocationCount) + ", middleWaypointCount=" +
        std::to_string(reportedLocationCount - 2) + ", maxWaypointCount=" + std::to_string(MAX_WAYPOINT_COUNT),
        "report SUCCESS with the newest 64 middle waypoints");
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    DataFabricAddressTest::SetShortDistanceResult(false);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ReportLocationPoints(reportedLocationCount);
    ASSERT_EQ(GetWaypointCount(), reportedLocationCount);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_END));
    ASSERT_EQ(callback->callCount, 1);
    EXPECT_EQ(callback->lastCode, StatusCode::SUCCESS);
    // The first and the last waypoints are reported separately, and the newest middle ones are kept.
    EXPECT_EQ(CountOccurrences(callback->lastResult, "\"timestamp\""), MAX_WAYPOINT_COUNT);
    EXPECT_EQ(callback->lastResult.find("\"latitude\":34,\"longitude\""), std::string::npos);
    EXPECT_NE(callback->lastResult.find("\"latitude\":35,\"longitude\""), std::string::npos);
    EXPECT_NE(callback->lastResult.find("\"startLatitude\":0"), std::string::npos);
    EXPECT_NE(callback->lastResult.find("\"endLatitude\":99"), std::string::npos);
    EXPECT_EQ(GetWaypointCount(), 0u);
    LogReportObservedResult("4", "SUCCESS");
}

/**
 * @tc.name: NavigationLiveViewObserver_ConstructReportResult_ReportSizeExceedMaximum_ReturnsFalse
 * @tc.desc: Test ConstructReportResult fails only because of the payload size, verified with a control call on the
 * same waypoints that succeeds with a normal bundle name.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_ConstructReportResult_ReportSizeExceedMaximum_ReturnsFalse, TestSize.Level0)
{
    LogReportScenario("5", "reportedLocations=" + std::to_string(MIN_WAYPOINT_COUNT) + ", controlBundleName=" +
        TARGET_BUNDLE_NAME + ", oversizeBundleNameLength=" + std::to_string(OVERSIZE_BUNDLE_NAME_LENGTH) +
        ", maxReportSize=" + std::to_string(REPORT_MAX_SIZE),
        "control returns true, the oversize payload returns false");
    sptr<TestDataFabricAddressCallbackStub> callback = MakeCallbackStub();
    PrepareReportScenario(callback);
    DataFabricAddressTest::SetShortDistanceResult(false);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    ASSERT_TRUE(SendLiveViewEvent(LiveViewEventType::LIVE_VIEW_START));
    ReportLocationPoints(MIN_WAYPOINT_COUNT);
    ASSERT_EQ(GetWaypointCount(), MIN_WAYPOINT_COUNT);
    LiveViewObserverImpl observer;
    std::string result;
    // Control: the same collected points with a target bundle name pass every other reporting check.
    ASSERT_TRUE(observer.ConstructReportResult(TEST_TIMESTAMP, TARGET_BUNDLE_NAME, result));
    ASSERT_LE(result.size(), REPORT_MAX_SIZE);
    const std::string oversizeBundleName(OVERSIZE_BUNDLE_NAME_LENGTH, 'a');
    EXPECT_FALSE(observer.ConstructReportResult(TEST_TIMESTAMP, oversizeBundleName, result));
    // The built payload is what exceeds the limit, so the failure comes from the size guard.
    EXPECT_GT(result.size(), REPORT_MAX_SIZE);
    LogReportObservedResult("5", "false");
    ZLOGI("[ConstructReportResult][Case5] oversizePayloadSize=%{public}zu", result.size());
}

class NavigationPassiveLocationHandlerTest : public DataCollectTestBase {};

/**
 * @tc.name: NavigationPassiveLocationHandler_SubscribePassiveLocation_ValidInput_SubscribeSuccess
 * @tc.desc: Test SubscribePassiveLocation starts locating with the expected request config.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_SubscribePassiveLocation_ValidInput_SubscribeSuccess, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    int32_t result = handler.SubscribePassiveLocation();
    EXPECT_EQ(result, RUN_OK);
    EXPECT_TRUE(handler.isSubscribed_.load());
    EXPECT_TRUE(handler.passiveCallback_ != nullptr);
    EXPECT_EQ(DataFabricAddressTest::GetStartLocatingCount(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLastRequestScenario(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLastRequestTimeInterval(), 1);
    EXPECT_EQ(DataFabricAddressTest::GetLastRequestDistanceInterval(), 10);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_SubscribePassiveLocation_AlreadySubscribed_ReturnsOk
 * @tc.desc: Test SubscribePassiveLocation is idempotent when the passive location has been subscribed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_SubscribePassiveLocation_AlreadySubscribed_ReturnsOk, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    ASSERT_EQ(handler.SubscribePassiveLocation(), RUN_OK);
    EXPECT_EQ(handler.SubscribePassiveLocation(), RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetStartLocatingCount(), 1);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_SubscribePassiveLocation_LocatorNull_ReturnsInternalException
 * @tc.desc: Test SubscribePassiveLocation fails when the locator instance is unavailable.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_SubscribePassiveLocation_LocatorNull_ReturnsInternalException, TestSize.Level0)
{
    DataFabricAddressTest::SetLocatorNull(true);
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    EXPECT_EQ(handler.SubscribePassiveLocation(), INTERNAL_EXCEPTION);
    EXPECT_FALSE(handler.isSubscribed_.load());
    EXPECT_EQ(DataFabricAddressTest::GetStartLocatingCount(), 0);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_SubscribePassiveLocation_StartFailed_ReturnsInternalException
 * @tc.desc: Test SubscribePassiveLocation fails when starting the locating fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_SubscribePassiveLocation_StartFailed_ReturnsInternalException, TestSize.Level0)
{
    DataFabricAddressTest::SetStartLocatingResult(1);
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    EXPECT_EQ(handler.SubscribePassiveLocation(), INTERNAL_EXCEPTION);
    EXPECT_FALSE(handler.isSubscribed_.load());
    EXPECT_TRUE(handler.passiveCallback_ == nullptr);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_UnsubscribePassiveLocation_NotSubscribed_ReturnsOk
 * @tc.desc: Test UnsubscribePassiveLocation returns ok when the passive location has not been subscribed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_UnsubscribePassiveLocation_NotSubscribed_ReturnsOk, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    EXPECT_EQ(handler.UnsubscribePassiveLocation(), RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetStopLocatingCount(), 0);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_UnsubscribePassiveLocation_NullCallback_ResetState
 * @tc.desc: Test UnsubscribePassiveLocation returns ok when the callback has been released.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_UnsubscribePassiveLocation_NullCallback_ResetState, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    handler.isSubscribed_.store(true);
    handler.passiveCallback_ = nullptr;
    EXPECT_EQ(handler.UnsubscribePassiveLocation(), RUN_OK);
    EXPECT_FALSE(handler.isSubscribed_.load());
    EXPECT_EQ(DataFabricAddressTest::GetStopLocatingCount(), 0);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_UnsubscribePassiveLocation_LocatorNull_ReturnsInternalException
 * @tc.desc: Test UnsubscribePassiveLocation fails when the locator instance is unavailable.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_UnsubscribePassiveLocation_LocatorNull_ReturnsInternalException,
    TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    ASSERT_EQ(handler.SubscribePassiveLocation(), RUN_OK);
    DataFabricAddressTest::SetLocatorNull(true);
    EXPECT_EQ(handler.UnsubscribePassiveLocation(), INTERNAL_EXCEPTION);
    EXPECT_TRUE(handler.isSubscribed_.load());
}

/**
 * @tc.name: NavigationPassiveLocationHandler_UnsubscribePassiveLocation_StopFailed_KeepState
 * @tc.desc: Test UnsubscribePassiveLocation keeps the state when stopping the locating fails.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_UnsubscribePassiveLocation_StopFailed_KeepState, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    ASSERT_EQ(handler.SubscribePassiveLocation(), RUN_OK);
    DataFabricAddressTest::SetStopLocatingResult(1);
    EXPECT_EQ(handler.UnsubscribePassiveLocation(), INTERNAL_EXCEPTION);
    EXPECT_TRUE(handler.isSubscribed_.load());
    EXPECT_TRUE(handler.passiveCallback_ != nullptr);
    EXPECT_EQ(DataFabricAddressTest::GetStopLocatingCount(), 1);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_UnsubscribePassiveLocation_ValidInput_ResetState
 * @tc.desc: Test UnsubscribePassiveLocation clears the state when stopping the locating succeeds.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_UnsubscribePassiveLocation_ValidInput_ResetState, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    ASSERT_EQ(handler.SubscribePassiveLocation(), RUN_OK);
    EXPECT_EQ(handler.UnsubscribePassiveLocation(), RUN_OK);
    EXPECT_FALSE(handler.isSubscribed_.load());
    EXPECT_TRUE(handler.passiveCallback_ == nullptr);
    EXPECT_EQ(DataFabricAddressTest::GetStopLocatingCount(), 1);
}

/**
 * @tc.name: NavigationPassiveLocationHandler_SubscribePassiveLocation_LocatorInFlight_HandlerLockNotHeld
 * @tc.desc: Test the locator is started while the handler lock is not held and the state is installed only after
 * the start returns.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_SubscribePassiveLocation_LocatorInFlight_HandlerLockNotHeld, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    bool lockAcquired = false;
    bool stateIsNotSubscribed = false;
    DataFabricAddressTest::SetLocatingCallHook([&handler, &lockAcquired, &stateIsNotSubscribed]() {
        if (!handler.mutex_.try_lock()) {
            return;
        }
        lockAcquired = true;
        stateIsNotSubscribed = !handler.isSubscribed_.load();
        handler.mutex_.unlock();
    });
    EXPECT_EQ(handler.SubscribePassiveLocation(), RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetStartLocatingCount(), 1);
    EXPECT_TRUE(lockAcquired);
    EXPECT_TRUE(stateIsNotSubscribed);
    EXPECT_TRUE(handler.isSubscribed_.load());
}

/**
 * @tc.name: NavigationPassiveLocationHandler_UnsubscribePassiveLocation_LocatorInFlight_HandlerLockNotHeld
 * @tc.desc: Test the locator is stopped while the handler lock is not held and the state is kept until it returns.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_UnsubscribePassiveLocation_LocatorInFlight_HandlerLockNotHeld, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    ASSERT_EQ(handler.SubscribePassiveLocation(), RUN_OK);
    bool lockAcquired = false;
    bool stateIsSubscribed = false;
    DataFabricAddressTest::SetLocatingCallHook([&handler, &lockAcquired, &stateIsSubscribed]() {
        if (!handler.mutex_.try_lock()) {
            return;
        }
        lockAcquired = true;
        stateIsSubscribed = handler.isSubscribed_.load() && handler.passiveCallback_ != nullptr;
        handler.mutex_.unlock();
    });
    EXPECT_EQ(handler.UnsubscribePassiveLocation(), RUN_OK);
    EXPECT_EQ(DataFabricAddressTest::GetStopLocatingCount(), 1);
    EXPECT_TRUE(lockAcquired);
    EXPECT_TRUE(stateIsSubscribed);
    EXPECT_FALSE(handler.isSubscribed_.load());
}

/**
 * @tc.name: NavigationPassiveLocationHandler_Waypoints_AddReadClear_WorkAsExpected
 * @tc.desc: Test AddWaypoints, ReadWaypoints and ClearWaypoints.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_Waypoints_AddReadClear_WorkAsExpected, TestSize.Level0)
{
    auto &handler = NavigationPassiveLocationHandler::GetInstance();
    handler.AddWaypoints({ 1, 31.0, 121.0 });
    handler.AddWaypoints({ 2, 31.1, 121.1 });
    std::vector<Waypoint> waypoints;
    handler.ReadWaypoints(waypoints);
    ASSERT_EQ(waypoints.size(), 2u);
    EXPECT_EQ(waypoints.front().timestamp, 1);
    EXPECT_EQ(waypoints.back().longitude, 121.1);
    handler.ClearWaypoints();
    handler.ReadWaypoints(waypoints);
    EXPECT_TRUE(waypoints.empty());
}

/**
 * @tc.name: NavigationPassiveLocationHandler_AddWaypoints_ExceedMaximum_KeepFirstAndLast
 * @tc.desc: Test AddWaypoints bounds the collected waypoints and keeps the first and the last one.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    NavigationPassiveLocationHandler_AddWaypoints_ExceedMaximum_KeepFirstAndLast, TestSize.Level0)
{
    const size_t totalCount = MAX_COLLECTED_WAYPOINT_COUNT + 5;
    AddTestWaypoints(totalCount);
    std::vector<Waypoint> waypoints;
    NavigationPassiveLocationHandler::GetInstance().ReadWaypoints(waypoints);
    ASSERT_EQ(waypoints.size(), MAX_COLLECTED_WAYPOINT_COUNT);
    // The trip start and the trip end are always kept.
    EXPECT_EQ(waypoints.front().timestamp, 0);
    EXPECT_EQ(waypoints.back().timestamp, static_cast<int64_t>(totalCount - 1));
    // The oldest middle waypoints are dropped first, so the second waypoint is the oldest remaining one.
    EXPECT_EQ(waypoints[1].timestamp, static_cast<int64_t>(totalCount - MAX_COLLECTED_WAYPOINT_COUNT + 1));
}

/**
 * @tc.name: PassiveLocatingCallback_OnRemoteRequest_InvalidToken_ReturnsFailedCode
 * @tc.desc: Test PassiveLocatingCallback OnRemoteRequest rejects the unmatched interface token.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnRemoteRequest_InvalidToken_ReturnsFailedCode, TestSize.Level0)
{
    PassiveLocatingCallback callback;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.location.UnknownCallback");
    EXPECT_EQ(callback.OnRemoteRequest(Location::ILocatorCallback::RECEIVE_ERROR_INFO_EVENT,
        data, reply, option), -1);
}

/**
 * @tc.name: PassiveLocatingCallback_OnRemoteRequest_ErrorEvent_ReturnsOk
 * @tc.desc: Test PassiveLocatingCallback OnRemoteRequest handles the error info event.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnRemoteRequest_ErrorEvent_ReturnsOk, TestSize.Level0)
{
    PassiveLocatingCallback callback;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(Location::ILocatorCallback::GetDescriptor());
    data.WriteInt32(1001);
    EXPECT_EQ(callback.OnRemoteRequest(Location::ILocatorCallback::RECEIVE_ERROR_INFO_EVENT,
        data, reply, option), RUN_OK);
}

/**
 * @tc.name: PassiveLocatingCallback_OnRemoteRequest_StatusEvent_ReturnsOk
 * @tc.desc: Test PassiveLocatingCallback OnRemoteRequest handles the locating status event.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnRemoteRequest_StatusEvent_ReturnsOk, TestSize.Level0)
{
    PassiveLocatingCallback callback;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(Location::ILocatorCallback::GetDescriptor());
    data.WriteInt32(1);
    EXPECT_EQ(callback.OnRemoteRequest(Location::ILocatorCallback::RECEIVE_LOCATION_STATUS_EVENT,
        data, reply, option), RUN_OK);
}

/**
 * @tc.name: PassiveLocatingCallback_OnRemoteRequest_UnknownCode_ReturnsOk
 * @tc.desc: Test PassiveLocatingCallback OnRemoteRequest ignores the unknown command code.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnRemoteRequest_UnknownCode_ReturnsOk, TestSize.Level0)
{
    PassiveLocatingCallback callback;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(Location::ILocatorCallback::GetDescriptor());
    EXPECT_EQ(callback.OnRemoteRequest(UNKNOWN_TRANSACTION_CODE, data, reply, option), RUN_OK);
}

/**
 * @tc.name: PassiveLocatingCallback_OnRemoteRequest_LocationEvent_AddWaypoint
 * @tc.desc: Test PassiveLocatingCallback OnRemoteRequest adds a waypoint when a valid location is reported.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnRemoteRequest_LocationEvent_AddWaypoint, TestSize.Level0)
{
    DataFabricAddressTest::SetNowSecondTimestamp(TEST_TIMESTAMP);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, LARGE_DISTANCE);
    StartNavigation();
    PassiveLocatingCallback callback;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(Location::ILocatorCallback::GetDescriptor());
    data.WriteDouble(31.2304);
    data.WriteDouble(121.4737);
    EXPECT_EQ(callback.OnRemoteRequest(Location::ILocatorCallback::RECEIVE_LOCATION_INFO_EVENT,
        data, reply, option), RUN_OK);
    std::vector<Waypoint> waypoints;
    NavigationPassiveLocationHandler::GetInstance().ReadWaypoints(waypoints);
    ASSERT_EQ(waypoints.size(), 1u);
    EXPECT_EQ(waypoints.front().timestamp, TEST_TIMESTAMP);
    EXPECT_EQ(waypoints.front().latitude, 31.2304);
    EXPECT_EQ(waypoints.front().longitude, 121.4737);
}

/**
 * @tc.name: PassiveLocatingCallback_OnRemoteRequest_TruncatedLocation_NoWaypoint
 * @tc.desc: Test PassiveLocatingCallback OnRemoteRequest ignores a truncated location report.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnRemoteRequest_TruncatedLocation_NoWaypoint, TestSize.Level0)
{
    StartNavigation();
    PassiveLocatingCallback callback;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(Location::ILocatorCallback::GetDescriptor());
    EXPECT_EQ(callback.OnRemoteRequest(Location::ILocatorCallback::RECEIVE_LOCATION_INFO_EVENT,
        data, reply, option), RUN_OK);
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: PassiveLocatingCallback_OnLocationReport_NullLocation_NoWaypoint
 * @tc.desc: Test PassiveLocatingCallback ignores a null location report.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnLocationReport_NullLocation_NoWaypoint, TestSize.Level0)
{
    StartNavigation();
    PassiveLocatingCallback callback;
    const std::unique_ptr<Location::Location> location = nullptr;
    callback.OnLocationReport(location);
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: PassiveLocatingCallback_OnLocationReport_ValidLocation_AddWaypoint
 * @tc.desc: Test PassiveLocatingCallback converts a valid location into a waypoint.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnLocationReport_ValidLocation_AddWaypoint, TestSize.Level0)
{
    DataFabricAddressTest::SetNowSecondTimestamp(TEST_TIMESTAMP);
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, LARGE_DISTANCE);
    StartNavigation();
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    std::vector<Waypoint> waypoints;
    NavigationPassiveLocationHandler::GetInstance().ReadWaypoints(waypoints);
    ASSERT_EQ(waypoints.size(), 1u);
    EXPECT_EQ(waypoints.front().timestamp, TEST_TIMESTAMP);
    EXPECT_EQ(waypoints.front().latitude, 31.2304);
    EXPECT_EQ(waypoints.front().longitude, 121.4737);
}

/**
 * @tc.name: PassiveLocatingCallback_OnErrorReportAndStatusChange_ValidInput_NoWaypoint
 * @tc.desc: Test PassiveLocatingCallback handles the error report and the locating status change.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnErrorReportAndStatusChange_ValidInput_NoWaypoint, TestSize.Level0)
{
    PassiveLocatingCallback callback;
    callback.OnErrorReport(1001);
    callback.OnLocatingStatusChange(1);
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: PassiveLocatingCallback_OnLocationReport_DistanceFailed_NoWaypoint
 * @tc.desc: Test the reported location is dropped when the distance cannot be calculated.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnLocationReport_DistanceFailed_NoWaypoint, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResult(false, 0.0);
    StartNavigation();
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: PassiveLocatingCallback_OnLocationReport_CompanyDistanceFailed_NoWaypoint
 * @tc.desc: Test the reported location is dropped when the distance to the company cannot be calculated.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnLocationReport_CompanyDistanceFailed_NoWaypoint, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceCallResults(true, false);
    StartNavigation();
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: PassiveLocatingCallback_OnLocationReport_FarFromReference_NoWaypoint
 * @tc.desc: Test the reported location is dropped when it is far from both home and company.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnLocationReport_FarFromReference_NoWaypoint, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResults(true, LARGE_DISTANCE, LARGE_DISTANCE);
    StartNavigation();
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    EXPECT_EQ(GetWaypointCount(), 0u);
}

/**
 * @tc.name: PassiveLocatingCallback_OnLocationReport_NearCompany_AddWaypoint
 * @tc.desc: Test the reported location is kept when it is near the company point.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnLocationReport_NearCompany_AddWaypoint, TestSize.Level0)
{
    DataFabricAddressTest::SetNowSecondTimestamp(TEST_TIMESTAMP);
    DataFabricAddressTest::SetGetDistanceResults(true, LARGE_DISTANCE, SMALL_DISTANCE);
    StartNavigation();
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    std::vector<Waypoint> waypoints;
    NavigationPassiveLocationHandler::GetInstance().ReadWaypoints(waypoints);
    ASSERT_EQ(waypoints.size(), 1u);
    EXPECT_EQ(waypoints.front().timestamp, TEST_TIMESTAMP);
    EXPECT_EQ(waypoints.front().latitude, 31.2304);
}

/**
 * @tc.name: PassiveLocatingCallback_OnLocationReport_NoActiveNavigation_NoWaypoint
 * @tc.desc: Test the passive location is dropped without any distance calculation when no navigation is in progress.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationPassiveLocationHandlerTest,
    PassiveLocatingCallback_OnLocationReport_NoActiveNavigation_NoWaypoint, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    ASSERT_FALSE(HasActiveNavigation());
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    EXPECT_EQ(GetWaypointCount(), 0u);
    EXPECT_EQ(DataFabricAddressTest::GetGetDistanceCallCount(), 0);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_StartEvent_ActivatePassiveLocation
 * @tc.desc: Test a navigation start event opens the passive location collection window.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_StartEvent_ActivatePassiveLocation, TestSize.Level0)
{
    AddTestWaypoints(2);
    sptr<LiveViewObserverImpl> observer = CreateMonitorObserver();
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    EXPECT_TRUE(HasActiveNavigation());
    EXPECT_EQ(GetWaypointCount(), 0u);

    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    EXPECT_EQ(GetWaypointCount(), 1u);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_EndEvent_DeactivatePassiveLocation
 * @tc.desc: Test a navigation end event closes the passive location collection window.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_EndEvent_DeactivatePassiveLocation, TestSize.Level0)
{
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    sptr<LiveViewObserverImpl> observer = CreateMonitorObserver();
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    ASSERT_TRUE(HasActiveNavigation());
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_FALSE(HasActiveNavigation());

    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    EXPECT_EQ(GetWaypointCount(), 0u);
    EXPECT_EQ(DataFabricAddressTest::GetGetDistanceCallCount(), 0);
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_DuplicateStart_KeepActiveNavigation
 * @tc.desc: Test a duplicated navigation start event does not increase the active navigation count.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_DuplicateStart_KeepActiveNavigation, TestSize.Level0)
{
    sptr<LiveViewObserverImpl> observer = CreateMonitorObserver();
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    EXPECT_TRUE(HasActiveNavigation());

    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_FALSE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_EndWithoutStart_KeepInactive
 * @tc.desc: Test the end event without a recorded start event does not make the active count negative.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_EndWithoutStart_KeepInactive, TestSize.Level0)
{
    sptr<LiveViewObserverImpl> observer = CreateMonitorObserver();
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME));
    EXPECT_FALSE(HasActiveNavigation());

    observer->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    EXPECT_TRUE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewObserver_OnLiveViewChanged_MultiTrip_KeepCollectingUntilLastEnd
 * @tc.desc: Test the passive location keeps collected until the last navigation trip ends.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewObserverTest,
    NavigationLiveViewObserver_OnLiveViewChanged_MultiTrip_KeepCollectingUntilLastEnd, TestSize.Level0)
{
    LiveViewEvent startEvent = MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME);
    LiveViewEvent endEvent = MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_END, TARGET_BUNDLE_NAME);
    LiveViewEvent anotherStartEvent = startEvent;
    anotherStartEvent.notificationId = TEST_NOTIFICATION_ID + 1;
    LiveViewEvent anotherEndEvent = endEvent;
    anotherEndEvent.notificationId = TEST_NOTIFICATION_ID + 1;

    sptr<LiveViewObserverImpl> observer = CreateMonitorObserver();
    observer->OnLiveViewChanged(startEvent);
    observer->OnLiveViewChanged(anotherStartEvent);
    ASSERT_TRUE(HasActiveNavigation());

    observer->OnLiveViewChanged(endEvent);
    EXPECT_TRUE(HasActiveNavigation());
    DataFabricAddressTest::SetGetDistanceResults(true, SMALL_DISTANCE, SMALL_DISTANCE);
    PassiveLocatingCallback callback;
    callback.OnLocationReport(std::make_unique<Location::Location>(31.2304, 121.4737));
    EXPECT_EQ(GetWaypointCount(), 1u);

    observer->OnLiveViewChanged(anotherEndEvent);
    EXPECT_FALSE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewMonitor_HasActiveNavigation_NotSubscribed_ReturnsFalse
 * @tc.desc: Test no active navigation is reported when the live view monitor has not been subscribed.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_HasActiveNavigation_NotSubscribed_ReturnsFalse, TestSize.Level0)
{
    EXPECT_TRUE(NavigationLiveViewMonitor::GetInstance().observer_ == nullptr);
    EXPECT_FALSE(HasActiveNavigation());
}

/**
 * @tc.name: NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_ResetActiveNavigation
 * @tc.desc: Test the active navigation follows the life cycle of the subscribed live view observer.
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(NavigationLiveViewMonitorTest,
    NavigationLiveViewMonitor_UnsubscribeNavigationLiveView_ResetActiveNavigation, TestSize.Level0)
{
    auto &monitor = NavigationLiveViewMonitor::GetInstance();
    ASSERT_EQ(SubscribeMonitor(MakeCallbackStub()), RUN_OK);
    ASSERT_TRUE(monitor.observer_ != nullptr);
    monitor.observer_->OnLiveViewChanged(MakeLiveViewEvent(LiveViewEventType::LIVE_VIEW_START, TARGET_BUNDLE_NAME));
    ASSERT_TRUE(HasActiveNavigation());

    ASSERT_EQ(monitor.UnsubscribeNavigationLiveView(), RUN_OK);
    EXPECT_TRUE(monitor.observer_ == nullptr);
    EXPECT_FALSE(HasActiveNavigation());

    // A new observer starts without any active navigation record.
    ASSERT_EQ(SubscribeMonitor(MakeCallbackStub()), RUN_OK);
    EXPECT_TRUE(monitor.observer_ != nullptr);
    EXPECT_FALSE(HasActiveNavigation());
}
