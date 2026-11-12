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

#include <functional>
#include <utility>
#include <vector>

#include "navigation_manager.h"

namespace {
int32_t g_subscribeResult = 0;
int32_t g_unsubscribeResult = 0;
int32_t g_unsubscribeManagerCount = 0;
std::vector<int32_t> g_subscribeActions;
std::function<void()> g_subscribeActionHook;
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
    if (g_subscribeActionHook != nullptr) {
        g_subscribeActionHook();
    }
    g_subscribeActions.push_back(static_cast<int32_t>(actionType));
    return g_subscribeResult;
}

int32_t NavigationManager::UnsubscribeNavigationManager()
{
    g_unsubscribeManagerCount++;
    return g_unsubscribeResult;
}
} // End of namespace DataFabricAddress

namespace DataFabricAddressTest {

void ResetNavigationManagerMock()
{
    g_subscribeResult = 0;
    g_unsubscribeResult = 0;
    g_unsubscribeManagerCount = 0;
    g_subscribeActions.clear();
    g_subscribeActionHook = nullptr;
}

void SetSubscribeNavigationManagerResult(int32_t result)
{
    g_subscribeResult = result;
}

void SetSubscribeNavigationManagerHook(std::function<void()> hook)
{
    g_subscribeActionHook = std::move(hook);
}

void SetUnsubscribeNavigationManagerResult(int32_t result)
{
    g_unsubscribeResult = result;
}

int32_t GetSubscribeActionCount()
{
    return static_cast<int32_t>(g_subscribeActions.size());
}

int32_t GetLastSubscribeAction()
{
    if (g_subscribeActions.empty()) {
        return -1;
    }
    return g_subscribeActions.back();
}

int32_t GetUnsubscribeManagerCallCount()
{
    return g_unsubscribeManagerCount;
}
} // End of namespace DataFabricAddressTest
} // End of namespace OHOS