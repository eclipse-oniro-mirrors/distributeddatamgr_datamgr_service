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

#include "navigation_manager.h"

#include "data_fabric_address_errors.h"
#include "log_print.h"

#undef LOG_TAG
#define LOG_TAG "NavigationManager"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;

NavigationManager &NavigationManager::GetInstance()
{
    static NavigationManager instance;
    return instance;
}

int32_t NavigationManager::SubscribeNavigationManager(const NativePreferences::ActionType& actionType,
    const NativePreferences::LocationPoint &homePoint, const NativePreferences::LocationPoint &companyPoint,
    const sptr<NativePreferences::IDataFabricAddressCallback> &callback)
{
    // The home/company coordinates are reserved interface parameters: this module currently does not store, persist,
    // or collect them.
    (void)homePoint;
    (void)companyPoint;
    ZLOGI("SubscribeNavigationManager enter, the input action is %{public}d", static_cast<int32_t>(actionType));
    if (actionType == NativePreferences::ActionType::SUBSCRIPTION) {
        return DoSubscribeAction(callback);
    } else if (actionType == NativePreferences::ActionType::UPDATE) {
        return DoUpdateAction();
    } else {
        ZLOGE("The input action is error.");
        return NativePreferences::PARAMETER_EXCEPTION;
    }
}

int32_t NavigationManager::UnsubscribeNavigationManager()
{
    ZLOGI("UnsubscribeNavigationManager enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isSubscribed_) {
        ZLOGI("Navigation manager has not been subscribed.");
        return NativePreferences::RUN_OK;
    }
    isSubscribed_ = false;
    ZLOGI("UnsubscribeNavigationManager exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationManager::DoSubscribeAction(
    const sptr<NativePreferences::IDataFabricAddressCallback> &callback)
{
    ZLOGI("DoSubscribeAction enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (isSubscribed_) {
        ZLOGI("Navigation manager has been subscribed.");
        return NativePreferences::RUN_OK;
    }
    // The callback is reserved for the reporting capability and is currently only checked to be non-null.
    if (callback == nullptr) {
        ZLOGE("The input callback is null.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    isSubscribed_ = true;
    ZLOGI("DoSubscribeAction exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationManager::DoUpdateAction()
{
    ZLOGI("DoUpdateAction enter.");
    // UPDATE only retains the subscription state check, keeping the original error code semantics (ABNORMAL/RUN_OK)
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isSubscribed_) {
        ZLOGE("Navigation manager has not subscribed, can't update.");
        return NativePreferences::ABNORMAL_OPERATION_EXCEPTION;
    }
    ZLOGI("DoUpdateAction exit.");
    return NativePreferences::RUN_OK;
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS
