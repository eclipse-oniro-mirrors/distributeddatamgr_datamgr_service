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

#ifndef NAVIGATION_MANAGER_H
#define NAVIGATION_MANAGER_H

#include <condition_variable>
#include <cstdint>
#include <mutex>

#include "data_fabric_address_callback.h"
#include "data_fabric_address_types.h"
#include "refbase.h"

namespace OHOS {
namespace DataFabricAddress {

class NavigationManager {
public:
    static NavigationManager &GetInstance();
    // The home/company coordinates are reserved interface parameters: this module currently does not store, persist,
    // or collect them.
    int32_t SubscribeNavigationManager(const NativePreferences::ActionType& actionType,
        const NativePreferences::LocationPoint &homePoint, const NativePreferences::LocationPoint &companyPoint,
        const sptr<NativePreferences::IDataFabricAddressCallback> &callback);
    int32_t UnsubscribeNavigationManager();
private:
    // mutex_ is held for the state transitions only, the dependencies are called outside of it because they
    // call their system ability synchronously. A caller which finds a transition in progress waits for it.
    enum class State {
        NOT_SUBSCRIBED,
        SUBSCRIBING,
        SUBSCRIBED,
        UNSUBSCRIBING,
    };

    NavigationManager() = default;
    ~NavigationManager() = default;
    int32_t DoSubscribeAction(const NativePreferences::LocationPoint &homePoint,
        const NativePreferences::LocationPoint &companyPoint,
        const sptr<NativePreferences::IDataFabricAddressCallback> &callback);
    int32_t DoUpdateAction(const NativePreferences::LocationPoint &homePoint,
        const NativePreferences::LocationPoint &companyPoint);
    // Waits for a transition in progress to settle, the caller passes its locked mutex_.
    void WaitForStableState(std::unique_lock<std::mutex> &lock);
    // Called without mutex_ held, after the dependencies of a transition have been handled.
    void FinishStateChange(State state);

    std::mutex mutex_;
    std::condition_variable stateCond_;
    State state_ = State::NOT_SUBSCRIBED;
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // NAVIGATION_MANAGER_H
