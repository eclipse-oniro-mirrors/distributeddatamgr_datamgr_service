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

#ifndef DATA_FABRIC_ADDRESS_NAVIGATION_MOCK_H
#define DATA_FABRIC_ADDRESS_NAVIGATION_MOCK_H

#include <cstdint>
#include <functional>

#include "data_fabric_address_types.h"

namespace OHOS {
namespace DataFabricAddressTest {

void ResetNavigationManagerMock();
void SetSubscribeNavigationManagerResult(int32_t result);
// The hook runs at the beginning of every SubscribeNavigationManager call, it lets a test observe
// the state of the caller while the navigation manager is being called.
void SetSubscribeNavigationManagerHook(std::function<void()> hook);
void SetUnsubscribeNavigationManagerResult(int32_t result);
int32_t GetSubscribeActionCount();
int32_t GetLastSubscribeAction();
int32_t GetUnsubscribeManagerCallCount();

void ResetNavigationCommonUtilsMock();
void SetGetDistanceResult(bool result, double distance);
// The first GetDistance call returns firstDistance, and the following calls return secondDistance.
void SetGetDistanceResults(bool result, double firstDistance, double secondDistance);
// Injects the result of each GetDistance call separately.
void SetGetDistanceCallResults(bool firstResult, bool secondResult);
void SetShortDistanceResult(bool result);
void SetGcj02ToWgs84Result(bool result);
void SetNowSecondTimestamp(int64_t timestamp);
int32_t GetGetDistanceCallCount();
// The call count and the last threshold of IsDistanceLessThan, used by the tests to prove
// which reporting branch a scenario reaches instead of only observing the report code.
int32_t GetIsDistanceLessThanCallCount();
double GetLastDistanceThreshold();

void ResetNavigationDataCollectMock();
void SetLiveViewSubscribeResult(int32_t result);
void SetLiveViewUnsubscribeResult(int32_t result);
void SetPassiveLocationSubscribeResult(int32_t result);
void SetPassiveLocationUnsubscribeResult(int32_t result);
int32_t GetLiveViewSubscribeCount();
int32_t GetLiveViewUnsubscribeCount();
int32_t GetPassiveLocationSubscribeCount();
int32_t GetPassiveLocationUnsubscribeCount();
bool GetLastReferenceLocation(NativePreferences::LocationPoint &homePoint,
    NativePreferences::LocationPoint &companyPoint);
// The hook runs at the beginning of every dependency call of the navigation manager, it lets a test
// observe the state and the lock of the manager while the dependency is being called.
void SetNavigationDataCollectHook(std::function<void()> hook);
int32_t GetNavigationDataCollectHookCallCount();
} // namespace DataFabricAddressTest
} // namespace OHOS
#endif // DATA_FABRIC_ADDRESS_NAVIGATION_MOCK_H
