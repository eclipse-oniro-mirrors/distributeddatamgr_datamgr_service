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

#include "locator_impl.h"

#include "location_mock.h"

namespace {
constexpr int32_t DEFAULT_SUCCESS = 0;
constexpr int32_t DEFAULT_INVALID_VALUE = -1;
bool g_locatorNull = false;
int32_t g_startLocatingResult = DEFAULT_SUCCESS;
int32_t g_stopLocatingResult = DEFAULT_SUCCESS;
int32_t g_startLocatingCount = 0;
int32_t g_stopLocatingCount = 0;
int32_t g_lastRequestScenario = DEFAULT_INVALID_VALUE;
int32_t g_lastRequestTimeInterval = DEFAULT_INVALID_VALUE;
int32_t g_lastRequestDistanceInterval = DEFAULT_INVALID_VALUE;
int32_t g_distanceBetweenLocationsResult = DEFAULT_SUCCESS;
double g_distanceBetweenLocationsValue = 0.0;
int32_t g_distanceBetweenLocationsCount = 0;
std::function<void()> g_locatingCallHook;

void InvokeLocatingCallHook()
{
    if (g_locatingCallHook) {
        g_locatingCallHook();
    }
}
} // namespace

namespace OHOS {
namespace Location {

std::unique_ptr<Location> Location::UnmarshallingMakeUnique(MessageParcel &data)
{
    double latitude = 0.0;
    double longitude = 0.0;
    if (!data.ReadDouble(latitude) || !data.ReadDouble(longitude)) {
        return nullptr;
    }
    return std::make_unique<Location>(latitude, longitude);
}

void RequestConfig::SetScenario(const Scenario &scenario)
{
    g_lastRequestScenario = static_cast<int32_t>(scenario);
}

void RequestConfig::SetTimeInterval(int32_t timeInterval)
{
    g_lastRequestTimeInterval = timeInterval;
}

void RequestConfig::SetDistanceInterval(int32_t distanceInterval)
{
    g_lastRequestDistanceInterval = distanceInterval;
}

LocatorImpl *LocatorImpl::GetInstance()
{
    if (g_locatorNull) {
        return nullptr;
    }
    static LocatorImpl instance;
    return &instance;
}

LocationErrCode LocatorImpl::StartLocatingV9(std::unique_ptr<RequestConfig> &requestConfig,
    sptr<ILocatorCallback> &callback)
{
    (void)requestConfig;
    (void)callback;
    InvokeLocatingCallHook();
    g_startLocatingCount++;
    return static_cast<LocationErrCode>(g_startLocatingResult);
}

LocationErrCode LocatorImpl::StopLocatingV9(const sptr<ILocatorCallback> &callback)
{
    (void)callback;
    InvokeLocatingCallHook();
    g_stopLocatingCount++;
    return static_cast<LocationErrCode>(g_stopLocatingResult);
}

LocationErrCode LocatorImpl::GetDistanceBetweenLocations(const Location &source, const Location &target,
    double &distance)
{
    (void)source;
    (void)target;
    g_distanceBetweenLocationsCount++;
    if (g_distanceBetweenLocationsResult != DEFAULT_SUCCESS) {
        return static_cast<LocationErrCode>(g_distanceBetweenLocationsResult);
    }
    distance = g_distanceBetweenLocationsValue;
    return ERRCODE_SUCCESS;
}
} // End of namespace Location
} // End of namespace OHOS

namespace OHOS {
namespace DataFabricAddressTest {

void ResetLocationMock()
{
    g_locatorNull = false;
    g_startLocatingResult = DEFAULT_SUCCESS;
    g_stopLocatingResult = DEFAULT_SUCCESS;
    g_startLocatingCount = 0;
    g_stopLocatingCount = 0;
    g_lastRequestScenario = DEFAULT_INVALID_VALUE;
    g_lastRequestTimeInterval = DEFAULT_INVALID_VALUE;
    g_lastRequestDistanceInterval = DEFAULT_INVALID_VALUE;
    g_distanceBetweenLocationsResult = DEFAULT_SUCCESS;
    g_distanceBetweenLocationsValue = 0.0;
    g_distanceBetweenLocationsCount = 0;
    g_locatingCallHook = nullptr;
}

void SetLocatingCallHook(std::function<void()> hook)
{
    g_locatingCallHook = hook;
}

void SetDistanceBetweenLocationsResult(int32_t result, double distance)
{
    g_distanceBetweenLocationsResult = result;
    g_distanceBetweenLocationsValue = distance;
}

int32_t GetDistanceBetweenLocationsCount()
{
    return g_distanceBetweenLocationsCount;
}

void SetLocatorNull(bool isNull)
{
    g_locatorNull = isNull;
}

void SetStartLocatingResult(int32_t result)
{
    g_startLocatingResult = result;
}

void SetStopLocatingResult(int32_t result)
{
    g_stopLocatingResult = result;
}

int32_t GetStartLocatingCount()
{
    return g_startLocatingCount;
}

int32_t GetStopLocatingCount()
{
    return g_stopLocatingCount;
}

int32_t GetLastRequestScenario()
{
    return g_lastRequestScenario;
}

int32_t GetLastRequestTimeInterval()
{
    return g_lastRequestTimeInterval;
}

int32_t GetLastRequestDistanceInterval()
{
    return g_lastRequestDistanceInterval;
}
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS
