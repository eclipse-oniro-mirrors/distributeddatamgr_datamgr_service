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
#include "data_fabric_address_event_dfx.h"
#include "log_print.h"
#include "navigation_live_view_monitor.h"
#include "navigation_passive_location_handler.h"

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
    ZLOGI("SubscribeNavigationManager enter, the input action is %{public}d", static_cast<int32_t>(actionType));
    int32_t ret = NativePreferences::PARAMETER_EXCEPTION;
    if (actionType == NativePreferences::ActionType::SUBSCRIPTION) {
        ret = DoSubscribeAction(homePoint, companyPoint, callback);
    } else if (actionType == NativePreferences::ActionType::UPDATE) {
        ret = DoUpdateAction(homePoint, companyPoint);
    } else {
        ZLOGE("The input action is error.");
    }
    RADAR_REPORT(CLIENT_REQUEST, NAVIGATION_SUBSCRIBE, ret == NativePreferences::RUN_OK ? RES_SUCCESS : RES_FAILED,
        "ERROR_CODE", ret);
    return ret;
}

int32_t NavigationManager::UnsubscribeNavigationManager()
{
    ZLOGI("UnsubscribeNavigationManager enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isSubscribed_) {
        ZLOGI("Navigation manager has not been subscribed.");
        return NativePreferences::RUN_OK;
    }

    int32_t ret = NavigationPassiveLocationHandler::GetInstance().UnsubscribePassiveLocation();
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Unsubscribe passive location failed.");
        RADAR_REPORT(CLIENT_REQUEST, NAVIGATION_UNSUBSCRIBE, RES_FAILED, "ERROR_CODE", ret);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    ret = NavigationLiveViewMonitor::GetInstance().UnsubscribeNavigationLiveView();
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Unsubscribe navigation live view failed.");
        RADAR_REPORT(CLIENT_REQUEST, NAVIGATION_UNSUBSCRIBE, RES_FAILED, "ERROR_CODE", ret);
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    isSubscribed_ = false;
    RADAR_REPORT(CLIENT_REQUEST, NAVIGATION_UNSUBSCRIBE, RES_SUCCESS);
    ZLOGI("UnsubscribeNavigationManager exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationManager::DoSubscribeAction(const NativePreferences::LocationPoint &homePoint,
    const NativePreferences::LocationPoint &companyPoint,
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

    int32_t ret = NavigationLiveViewMonitor::GetInstance().SubscribeNavigationLiveView(
        homePoint, companyPoint, callback);
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Subscribe navigation live view failed.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    ret = NavigationPassiveLocationHandler::GetInstance().SubscribePassiveLocation();
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Subscribe passive location failed.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    isSubscribed_ = true;
    ZLOGI("DoSubscribeAction exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationManager::DoUpdateAction(const NativePreferences::LocationPoint &homePoint,
    const NativePreferences::LocationPoint &companyPoint)
{
    ZLOGI("DoUpdateAction enter.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (!isSubscribed_) {
        ZLOGE("Navigation manager has not subscribed, can't update.");
        return NativePreferences::ABNORMAL_OPERATION_EXCEPTION;
    }
    NavigationLiveViewMonitor::GetInstance().UpdateReferenceLocation(homePoint, companyPoint);
    ZLOGI("DoUpdateAction exit.");
    return NativePreferences::RUN_OK;
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS
