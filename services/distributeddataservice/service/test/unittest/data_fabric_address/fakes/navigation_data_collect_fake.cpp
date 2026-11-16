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

#include "navigation_mock.h"

#include "data_fabric_address_errors.h"
#include "navigation_live_view_monitor.h"
#include "navigation_passive_location_handler.h"

namespace {
constexpr int32_t DEFAULT_RESULT = 0;
bool g_hasReferenceLocation = false;
OHOS::NativePreferences::LocationPoint g_homePoint = {
    OHOS::NativePreferences::DEFAULT_INVALID_LAT_VALUE, OHOS::NativePreferences::DEFAULT_INVALID_LNG_VALUE
};
OHOS::NativePreferences::LocationPoint g_companyPoint = {
    OHOS::NativePreferences::DEFAULT_INVALID_LAT_VALUE, OHOS::NativePreferences::DEFAULT_INVALID_LNG_VALUE
};
int32_t g_liveViewSubscribeResult = DEFAULT_RESULT;
int32_t g_liveViewUnsubscribeResult = DEFAULT_RESULT;
int32_t g_passiveSubscribeResult = DEFAULT_RESULT;
int32_t g_passiveUnsubscribeResult = DEFAULT_RESULT;
int32_t g_liveViewSubscribeCount = 0;
int32_t g_liveViewUnsubscribeCount = 0;
int32_t g_passiveSubscribeCount = 0;
int32_t g_passiveUnsubscribeCount = 0;
std::function<void()> g_dataCollectHook;
int32_t g_dataCollectHookCount = 0;

void InvokeDataCollectHook()
{
    g_dataCollectHookCount++;
    if (g_dataCollectHook) {
        g_dataCollectHook();
    }
}
} // namespace

namespace OHOS {
namespace DataFabricAddress {
using namespace NativePreferences;

NavigationLiveViewMonitor &NavigationLiveViewMonitor::GetInstance()
{
    static NavigationLiveViewMonitor instance;
    return instance;
}

int32_t NavigationLiveViewMonitor::SubscribeNavigationLiveView(const LocationPoint &homePoint,
    const LocationPoint &companyPoint, const sptr<IDataFabricAddressCallback> &callback)
{
    (void)callback;
    InvokeDataCollectHook();
    g_liveViewSubscribeCount++;
    if (g_liveViewSubscribeResult == RUN_OK) {
        g_homePoint = homePoint;
        g_companyPoint = companyPoint;
        g_hasReferenceLocation = true;
    }
    return g_liveViewSubscribeResult;
}

void NavigationLiveViewMonitor::UpdateReferenceLocation(const LocationPoint &homePoint,
    const LocationPoint &companyPoint)
{
    InvokeDataCollectHook();
    g_homePoint = homePoint;
    g_companyPoint = companyPoint;
    g_hasReferenceLocation = true;
}

int32_t NavigationLiveViewMonitor::UnsubscribeNavigationLiveView()
{
    InvokeDataCollectHook();
    g_liveViewUnsubscribeCount++;
    return g_liveViewUnsubscribeResult;
}

NavigationPassiveLocationHandler &NavigationPassiveLocationHandler::GetInstance()
{
    static NavigationPassiveLocationHandler instance;
    return instance;
}

int32_t NavigationPassiveLocationHandler::SubscribePassiveLocation()
{
    InvokeDataCollectHook();
    g_passiveSubscribeCount++;
    return g_passiveSubscribeResult;
}

int32_t NavigationPassiveLocationHandler::UnsubscribePassiveLocation()
{
    InvokeDataCollectHook();
    g_passiveUnsubscribeCount++;
    return g_passiveUnsubscribeResult;
}
} // End of namespace DataFabricAddress

namespace DataFabricAddressTest {

void ResetNavigationDataCollectMock()
{
    g_hasReferenceLocation = false;
    g_homePoint = { NativePreferences::DEFAULT_INVALID_LAT_VALUE, NativePreferences::DEFAULT_INVALID_LNG_VALUE };
    g_companyPoint = { NativePreferences::DEFAULT_INVALID_LAT_VALUE, NativePreferences::DEFAULT_INVALID_LNG_VALUE };
    g_liveViewSubscribeResult = DEFAULT_RESULT;
    g_liveViewUnsubscribeResult = DEFAULT_RESULT;
    g_passiveSubscribeResult = DEFAULT_RESULT;
    g_passiveUnsubscribeResult = DEFAULT_RESULT;
    g_liveViewSubscribeCount = 0;
    g_liveViewUnsubscribeCount = 0;
    g_passiveSubscribeCount = 0;
    g_passiveUnsubscribeCount = 0;
    g_dataCollectHook = nullptr;
    g_dataCollectHookCount = 0;
}

void SetNavigationDataCollectHook(std::function<void()> hook)
{
    g_dataCollectHook = hook;
}

int32_t GetNavigationDataCollectHookCallCount()
{
    return g_dataCollectHookCount;
}

void SetLiveViewSubscribeResult(int32_t result)
{
    g_liveViewSubscribeResult = result;
}

void SetLiveViewUnsubscribeResult(int32_t result)
{
    g_liveViewUnsubscribeResult = result;
}

void SetPassiveLocationSubscribeResult(int32_t result)
{
    g_passiveSubscribeResult = result;
}

void SetPassiveLocationUnsubscribeResult(int32_t result)
{
    g_passiveUnsubscribeResult = result;
}

int32_t GetLiveViewSubscribeCount()
{
    return g_liveViewSubscribeCount;
}

int32_t GetLiveViewUnsubscribeCount()
{
    return g_liveViewUnsubscribeCount;
}

int32_t GetPassiveLocationSubscribeCount()
{
    return g_passiveSubscribeCount;
}

int32_t GetPassiveLocationUnsubscribeCount()
{
    return g_passiveUnsubscribeCount;
}

bool GetLastReferenceLocation(NativePreferences::LocationPoint &homePoint,
    NativePreferences::LocationPoint &companyPoint)
{
    homePoint = g_homePoint;
    companyPoint = g_companyPoint;
    return g_hasReferenceLocation;
}
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS
