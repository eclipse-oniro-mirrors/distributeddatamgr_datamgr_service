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

#include "navigation_manager.h"

namespace {
int32_t g_subscribeResult = 0;
int32_t g_unsubscribeResult = 0;
} // namespace

namespace OHOS {
namespace DataFabricAddress {
using namespace NativePreferences;

NavigationManager &NavigationManager::GetInstance()
{
    static NavigationManager instance;
    return instance;
}

int32_t NavigationManager::SubscribeNavigationManager(const ActionType& actionType,
    const LocationPoint &homePoint, const LocationPoint &companyPoint,
    const sptr<IDataFabricAddressCallback> &callback)
{
    return g_subscribeResult;
}

int32_t NavigationManager::UnsubscribeNavigationManager()
{
    return g_unsubscribeResult;
}
} // End of namespace DataFabricAddress

namespace DataFabricAddressTest {

void ResetNavigationManagerMock()
{
    g_subscribeResult = 0;
    g_unsubscribeResult = 0;
}

void SetSubscribeNavigationManagerResult(int32_t result)
{
    g_subscribeResult = result;
}

void SetUnsubscribeNavigationManagerResult(int32_t result)
{
    g_unsubscribeResult = result;
}
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS