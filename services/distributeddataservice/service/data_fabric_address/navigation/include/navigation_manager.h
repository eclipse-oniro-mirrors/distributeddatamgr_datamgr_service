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
    NavigationManager() = default;
    ~NavigationManager() = default;
    int32_t DoSubscribeAction(const sptr<NativePreferences::IDataFabricAddressCallback> &callback);
    int32_t DoUpdateAction();

    std::mutex mutex_;          // Protects the state field (isSubscribed_)
    bool isSubscribed_ = false;
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // NAVIGATION_MANAGER_H
