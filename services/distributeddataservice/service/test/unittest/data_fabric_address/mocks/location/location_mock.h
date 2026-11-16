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

#ifndef LOCATION_MOCK_LOCATION_MOCK_H
#define LOCATION_MOCK_LOCATION_MOCK_H

#include <cstdint>
#include <functional>

namespace OHOS {
namespace DataFabricAddressTest {

void ResetLocationMock();
void SetLocatorNull(bool isNull);
void SetStartLocatingResult(int32_t result);
void SetStopLocatingResult(int32_t result);
int32_t GetStartLocatingCount();
int32_t GetStopLocatingCount();
int32_t GetLastRequestScenario();
int32_t GetLastRequestTimeInterval();
int32_t GetLastRequestDistanceInterval();
void SetDistanceBetweenLocationsResult(int32_t result, double distance);
int32_t GetDistanceBetweenLocationsCount();
// The hook runs at the beginning of StartLocatingV9 and StopLocatingV9, it lets a test observe the
// lock of the passive location handler while the locator service is being called.
void SetLocatingCallHook(std::function<void()> hook);
} // namespace DataFabricAddressTest
} // namespace OHOS
#endif // LOCATION_MOCK_LOCATION_MOCK_H
