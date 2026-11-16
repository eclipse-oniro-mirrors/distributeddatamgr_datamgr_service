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
    bool wasSubscribed = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        WaitForStableState(lock);
        // The dependencies are always torn down, even when the manager is not subscribed. A partial failure
        // leaves the state NOT_SUBSCRIBED but may leave one dependency subscribed, retrying releases it.
        wasSubscribed = state_ == State::SUBSCRIBED;
        if (!wasSubscribed) {
            ZLOGI("Navigation manager has not been subscribed, retry the dependencies.");
        }
        state_ = State::UNSUBSCRIBING;
    }

    // The UNSUBSCRIBING state keeps the other actions out while the dependencies are torn down.
    int32_t passiveRet = NavigationPassiveLocationHandler::GetInstance().UnsubscribePassiveLocation();
    if (passiveRet != NativePreferences::RUN_OK) {
        ZLOGE("Unsubscribe passive location failed, ret:%{public}d", passiveRet);
    }
    // The live view is torn down even when the passive location fails, otherwise its cached subscription
    // and geofence callback are left behind.
    int32_t liveViewRet = NavigationLiveViewMonitor::GetInstance().UnsubscribeNavigationLiveView();
    if (liveViewRet != NativePreferences::RUN_OK) {
        ZLOGE("Unsubscribe navigation live view failed, ret:%{public}d", liveViewRet);
    }
    FinishStateChange(State::NOT_SUBSCRIBED);

    // The events are reported outside the manager lock, the write may block.
    if (passiveRet != NativePreferences::RUN_OK) {
        RADAR_REPORT(CLIENT_REQUEST, NAVIGATION_UNSUBSCRIBE, RES_FAILED, "ERROR_CODE", passiveRet);
    }
    if (liveViewRet != NativePreferences::RUN_OK) {
        RADAR_REPORT(CLIENT_REQUEST, NAVIGATION_UNSUBSCRIBE, RES_FAILED, "ERROR_CODE", liveViewRet);
    }
    if (passiveRet != NativePreferences::RUN_OK || liveViewRet != NativePreferences::RUN_OK) {
        // The next subscription rebuilds both dependencies instead of returning a fake success.
        ZLOGI("UnsubscribeNavigationManager exit with a partial failure.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    if (wasSubscribed) {
        RADAR_REPORT(CLIENT_REQUEST, NAVIGATION_UNSUBSCRIBE, RES_SUCCESS);
    }
    ZLOGI("UnsubscribeNavigationManager exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationManager::DoSubscribeAction(const NativePreferences::LocationPoint &homePoint,
    const NativePreferences::LocationPoint &companyPoint,
    const sptr<NativePreferences::IDataFabricAddressCallback> &callback)
{
    ZLOGI("DoSubscribeAction enter.");
    {
        std::unique_lock<std::mutex> lock(mutex_);
        WaitForStableState(lock);
        if (state_ == State::SUBSCRIBED) {
            ZLOGI("Navigation manager has been subscribed.");
            return NativePreferences::RUN_OK;
        }
        // The callback is reserved for the reporting capability and is currently only checked to be non-null.
        if (callback == nullptr) {
            ZLOGE("The input callback is null.");
            return NativePreferences::INTERNAL_EXCEPTION;
        }
        state_ = State::SUBSCRIBING;
    }

    // The SUBSCRIBING state keeps the other actions out while the dependencies are subscribed.
    int32_t ret = NavigationLiveViewMonitor::GetInstance().SubscribeNavigationLiveView(
        homePoint, companyPoint, callback);
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Subscribe navigation live view failed.");
        FinishStateChange(State::NOT_SUBSCRIBED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    ret = NavigationPassiveLocationHandler::GetInstance().SubscribePassiveLocation();
    if (ret != NativePreferences::RUN_OK) {
        ZLOGE("Subscribe passive location failed, roll back the live view subscription.");
        // The live view was subscribed in this action, roll it back so that its geofence callback does not
        // keep firing for a manager which is not subscribed.
        int32_t rollbackRet = NavigationLiveViewMonitor::GetInstance().UnsubscribeNavigationLiveView();
        if (rollbackRet != NativePreferences::RUN_OK) {
            ZLOGW("Roll back the live view subscription failed, ret:%{public}d", rollbackRet);
        }
        FinishStateChange(State::NOT_SUBSCRIBED);
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    FinishStateChange(State::SUBSCRIBED);
    ZLOGI("DoSubscribeAction exit.");
    return NativePreferences::RUN_OK;
}

int32_t NavigationManager::DoUpdateAction(const NativePreferences::LocationPoint &homePoint,
    const NativePreferences::LocationPoint &companyPoint)
{
    ZLOGI("DoUpdateAction enter.");
    {
        std::unique_lock<std::mutex> lock(mutex_);
        WaitForStableState(lock);
        if (state_ != State::SUBSCRIBED) {
            ZLOGE("Navigation manager has not subscribed, can't update.");
            return NativePreferences::ABNORMAL_OPERATION_EXCEPTION;
        }
    }
    // The monitor protects the reference points by its own lock.
    NavigationLiveViewMonitor::GetInstance().UpdateReferenceLocation(homePoint, companyPoint);
    ZLOGI("DoUpdateAction exit.");
    return NativePreferences::RUN_OK;
}

void NavigationManager::WaitForStableState(std::unique_lock<std::mutex> &lock)
{
    stateCond_.wait(lock, [this]() {
        return state_ != State::SUBSCRIBING && state_ != State::UNSUBSCRIBING;
    });
}

void NavigationManager::FinishStateChange(State state)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        state_ = state;
    }
    // Notified outside the lock so that the woken caller does not block on it again.
    stateCond_.notify_all();
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS
