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

namespace OHOS {
namespace DataFabricAddressTest {

void ResetNavigationManagerMock();
void SetSubscribeNavigationManagerResult(int32_t result);
void SetUnsubscribeNavigationManagerResult(int32_t result);

void ResetNavigationCommonUtilsMock();
void SetGetDistanceResult(bool result, double distance);
void SetGcj02ToWgs84Result(bool result);
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_NAVIGATION_MOCK_H
