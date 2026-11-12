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

#include "data_fabric_address_service_impl.h"

#include <vector>

#include "data_fabric_address_errors.h"
#include "data_fabric_address_event_dfx.h"
#include "data_fabric_address_types.h"
#include "ipc_skeleton.h"
#include "log_print.h"
#include "navigation_common_utils.h"
#include "navigation_manager.h"
#include "system_ability_definition.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressServiceImpl"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;
// Maximum count of reference points supported by the commuting scenario
constexpr size_t NAVIGATION_REFERENCE_POINTS_MAX_COUNT { 2 };

__attribute__((used)) DataFabricAddressServiceImpl::Factory DataFabricAddressServiceImpl::factory_;

DataFabricAddressServiceImpl::Factory::Factory()
{
    ZLOGI("Register data_fabric_address creator.");
    FeatureSystem::GetInstance().RegisterCreator("data_fabric_address", []() {
        return std::make_shared<DataFabricAddressServiceImpl>();
    });
    staticActs_ = std::make_shared<DataFabricAddressStatic>();
    FeatureSystem::GetInstance().RegisterStaticActs("data_fabric_address", staticActs_);
    ZLOGI("Register data_fabric_address creator finished.");
}

DataFabricAddressServiceImpl::Factory::~Factory()
{
}

bool DataFabricAddressServiceImpl::Factory::IsInited()
{
    return staticActs_ && staticActs_->IsAbilityInited();
}

bool DataFabricAddressServiceImpl::DataFabricAddressStatic::IsAbilityInited()
{
    return isInited_.load();
}

int32_t DataFabricAddressServiceImpl::DataFabricAddressStatic::OnSystemAbilityAdded(
    int32_t systemAbilityId, const std::string &deviceId)
{
    ZLOGI("OnSystemAbilityAdded enter, systemAbilityId=%{public}d", systemAbilityId);
    if (systemAbilityId == LOCATION_LOCATOR_SA_ID) {
        if (!isInited_) {
            ZLOGI("All needed system ability has been initialized.");
            isInited_ = true;
        }
    }
    return RUN_OK;
}

int32_t DataFabricAddressServiceImpl::DataFabricAddressStatic::OnSystemAbilityRemoved(
    int32_t systemAbilityId, const std::string &deviceId)
{
    ZLOGI("OnSystemAbilityRemoved enter, systemAbilityId=%{public}d", systemAbilityId);
    if (systemAbilityId == LOCATION_LOCATOR_SA_ID) {
        isInited_ = false;
    }
    return RUN_OK;
}

int32_t DataFabricAddressServiceImpl::Subscribe(const DataFabricAddressParams& inputParams,
    sptr<IDataFabricAddressCallback> callback)
{
    ZLOGI("Service Subscribe enter.");
    PreparedSubscription prepared;
    {
        // The lock protects the subscription cache only. The navigation manager is called after it is
        // released because it subscribes the geofence and locator services synchronously, and the
        // event reporting is also done outside so that a slow event write never blocks the cache.
        std::lock_guard<std::mutex> lock(subscribersMutex_);
        prepared = PrepareSubscription(inputParams, callback);
    }
    if (prepared.status != RUN_OK) {
        RADAR_REPORT(CLIENT_REQUEST, DATA_FABRIC_ADDRESS_SUBSCRIBE, RES_FAILED, "ERROR_CODE",
            prepared.errorCode);
        return prepared.status;
    }

    ActionType actionType = inputParams.locationInfo.actionType;
    if (actionType == ActionType::UPDATE) {
        // The SA may have restarted and lost the subscription state, re-establish it before the update.
        int32_t subRet = NavigationManager::GetInstance().SubscribeNavigationManager(ActionType::SUBSCRIPTION,
            prepared.homePoint, prepared.companyPoint, prepared.callback);
        if (subRet != RUN_OK) {
            ZLOGE("Failed to re-establish the subscription state.");
            RADAR_REPORT(CLIENT_REQUEST, DATA_FABRIC_ADDRESS_SUBSCRIBE, RES_FAILED, "ERROR_CODE",
                NAVIGATION_SUBSCRIBE_FAILED);
            return subRet;
        }
    }
    int32_t status = NavigationManager::GetInstance().SubscribeNavigationManager(
        actionType, prepared.homePoint, prepared.companyPoint, prepared.callback);
    if (status != RUN_OK && actionType == ActionType::SUBSCRIPTION && !prepared.hasCachedParams) {
        // A newly cached subscription which failed to start must not keep the single subscriber slot
        // occupied, otherwise no other caller can subscribe until this caller unsubscribes.
        std::lock_guard<std::mutex> lock(subscribersMutex_);
        RollbackCachedSubscription(inputParams);
    }
    RADAR_REPORT(CLIENT_REQUEST, DATA_FABRIC_ADDRESS_SUBSCRIBE,
        status == RUN_OK ? RES_SUCCESS : RES_FAILED, "ERROR_CODE", status);
    return status;
}

DataFabricAddressServiceImpl::PreparedSubscription DataFabricAddressServiceImpl::PrepareSubscription(
    const DataFabricAddressParams& inputParams, const sptr<IDataFabricAddressCallback>& callback)
{
    PreparedSubscription prepared;
    if (!factory_.IsInited()) {
        ZLOGE("System ability not initialized.");
        prepared.status = INTERNAL_EXCEPTION;
        prepared.errorCode = SYSTEM_ABILITY_NOT_INITED;
        return prepared;
    }
    // The navigation collectors are singletons with a single callback slot, so only one subscription
    // exists at a time. Rejecting a conflicting one avoids returning a fake success and keeps the
    // cached callback and the reference points of the existing subscriber intact.
    if (IsSubscriptionOccupied(inputParams)) {
        ZLOGE("The subscription is occupied, only one subscriber is supported.");
        prepared.status = SUBSCRIBE_EXCEPTION;
        prepared.errorCode = ADD_CALLBACK_FAILED;
        return prepared;
    }
    int32_t ret = ValidateParams(inputParams, prepared.homePoint, prepared.companyPoint);
    if (ret != RUN_OK) {
        prepared.status = ret;
        prepared.errorCode = ret;
        return prepared;
    }
    // The pre-existing entry must be read before AddCallback inserts the new one, otherwise every
    // subscription looks already cached and a failed one is never rolled back, which keeps the single
    // subscriber slot occupied. The cached callback is the owner of the subscription, use it so that a
    // repeated subscription cannot replace the callback used for reporting.
    const auto cachedIter = subscribeCacheMap_.find(inputParams);
    prepared.hasCachedParams = cachedIter != subscribeCacheMap_.end();
    if (!AddCallback(inputParams, callback)) {
        prepared.status = INTERNAL_EXCEPTION;
        prepared.errorCode = ADD_CALLBACK_FAILED;
        return prepared;
    }
    prepared.callback = callback;
    if (prepared.hasCachedParams && cachedIter->second.callback != nullptr) {
        prepared.callback = cachedIter->second.callback;
    }
    return prepared;
}

void DataFabricAddressServiceImpl::RollbackCachedSubscription(const DataFabricAddressParams& inputParams)
{
    const auto iter = subscribeCacheMap_.find(inputParams);
    if (iter == subscribeCacheMap_.end()) {
        return;
    }
    sptr<IRemoteObject> object { nullptr };
    if (iter->second.callback != nullptr) {
        object = iter->second.callback->AsObject();
    }
    sptr<IRemoteObject::DeathRecipient> deathRecipient = iter->second.cbDeathRecipient;
    subscribeCacheMap_.erase(iter);
    if (object != nullptr && deathRecipient != nullptr) {
        object->RemoveDeathRecipient(deathRecipient);
    }
    ZLOGW("Roll back the cached subscription of the failed subscribe.");
}

bool DataFabricAddressServiceImpl::AddCallback(const DataFabricAddressParams& inputParams,
    sptr<IDataFabricAddressCallback> callback)
{
    ZLOGI("Service AddCallback enter.");
    if (inputParams.locationInfo.actionType == ActionType::UPDATE) {
        ZLOGI("The update action do not need to add callback.");
        return true;
    }
    // A repeated subscription of the same params keeps the cached callback. Registering another
    // death recipient for it would leak the recipient because the map insertion is skipped.
    if (subscribeCacheMap_.find(inputParams) != subscribeCacheMap_.end()) {
        ZLOGI("The subscription has been cached, keep the cached callback.");
        return true;
    }
    auto object = callback->AsObject();
    if (object == nullptr) {
        ZLOGE("The callback remote is null.");
        return false;
    }
    sptr<DeathRecipientListener> cbDeathRecipient = new (std::nothrow) DeathRecipientListener(weak_from_this());
    if (cbDeathRecipient == nullptr) {
        ZLOGE("Failed to create cbDeathRecipient.");
        return false;
    }
    object->AddDeathRecipient(cbDeathRecipient);
    const uint64_t callerToken = IPCSkeleton::GetCallingFullTokenID();
    auto result = subscribeCacheMap_.emplace(inputParams, SubscribeCacheData{cbDeathRecipient, callback,
        callerToken});
    if (!result.second) {
        object->RemoveDeathRecipient(cbDeathRecipient);
        ZLOGE("Failed to cache the subscription.");
        return false;
    }
    // Only the owner of the cached subscription may retry the navigation manager tear down after its
    // cache entry has been removed by the first unsubscription.
    lastSubscribedToken_ = callerToken;
    ZLOGI("Service AddCallback exit.");
    return true;
}

bool DataFabricAddressServiceImpl::IsSubscriptionOccupied(const DataFabricAddressParams& inputParams) const
{
    if (subscribeCacheMap_.empty()) {
        // Nothing is cached, the subscription or the update can rebuild the state freely.
        return false;
    }
    const uint64_t callerToken = IPCSkeleton::GetCallingFullTokenID();
    if (inputParams.locationInfo.actionType == ActionType::UPDATE) {
        // The update reuses the subscription of the same caller. The reference points are a part of the
        // cache key, so an update with new points is matched by the caller instead of by the key.
        for (const auto &entry : subscribeCacheMap_) {
            if (entry.second.callerFullTokenId != callerToken) {
                ZLOGW("The subscription is owned by another caller.");
                return true;
            }
        }
        return false;
    }
    // Only one subscription exists, a new one is accepted only when it repeats the cached params of the
    // same caller. Changing the reference points of an existing subscription requires an update action.
    const auto iter = subscribeCacheMap_.find(inputParams);
    if (iter != subscribeCacheMap_.end() && iter->second.callerFullTokenId == callerToken) {
        return false;
    }
    ZLOGW("The subscription is occupied, the params or the caller does not match the cached subscription.");
    return true;
}

int32_t DataFabricAddressServiceImpl::Unsubscribe(const DataFabricAddressParams& inputParams)
{
    ZLOGI("Service Unsubscribe enter.");
    sptr<IRemoteObject> callbackObject { nullptr };
    sptr<IRemoteObject::DeathRecipient> deathRecipient { nullptr };
    int32_t result = RUN_OK;
    int32_t errorCode = INTERNAL_EXCEPTION;
    bool removed = false;
    {
        std::lock_guard<std::mutex> lock(subscribersMutex_);
        if (!factory_.IsInited()) {
            ZLOGE("System ability not initialized.");
            result = INTERNAL_EXCEPTION;
            errorCode = SYSTEM_ABILITY_NOT_INITED;
        } else {
            result = RemoveCallback(inputParams, callbackObject, deathRecipient, removed);
            if (result != RUN_OK) {
                errorCode = REMOVE_CALLBACK_FAILED;
            }
        }
    }
    if (result != RUN_OK) {
        // The event is reported outside the cache lock, the write may block.
        RADAR_REPORT(CLIENT_REQUEST, DATA_FABRIC_ADDRESS_UNSUBSCRIBE, RES_FAILED, "ERROR_CODE", errorCode);
        return result;
    }
    if (!removed) {
        // The caller does not own the subscription, it must not stop the collection of another caller.
        ZLOGI("Service Unsubscribe exit, the caller does not own the subscription.");
        RADAR_REPORT(CLIENT_REQUEST, DATA_FABRIC_ADDRESS_UNSUBSCRIBE, RES_SUCCESS);
        return RUN_OK;
    }

    if (callbackObject != nullptr && deathRecipient != nullptr) {
        callbackObject->RemoveDeathRecipient(deathRecipient);
    }
    int32_t status = NavigationManager::GetInstance().UnsubscribeNavigationManager();
    RADAR_REPORT(CLIENT_REQUEST, DATA_FABRIC_ADDRESS_UNSUBSCRIBE,
        status == RUN_OK ? RES_SUCCESS : RES_FAILED, "ERROR_CODE", status);
    return status;
}

int32_t DataFabricAddressServiceImpl::RemoveCallback(const DataFabricAddressParams& inputParams,
    sptr<IRemoteObject>& callbackObject, sptr<IRemoteObject::DeathRecipient>& deathRecipient, bool& removed)
{
    ZLOGI("Service RemoveCallback enter.");
    removed = false;
    const auto iter = subscribeCacheMap_.find(inputParams);
    if (iter == subscribeCacheMap_.end()) {
        // The cache entry is removed before the navigation manager is torn down, so the owner retries the
        // tear down with an entry which no longer exists. Any other caller is treated as already
        // unsubscribed and is not allowed to stop the collection with arbitrary params.
        removed = IPCSkeleton::GetCallingFullTokenID() == lastSubscribedToken_;
        if (removed) {
            ZLOGW("The params are not cached, only the owner retries the tear down.");
        } else {
            ZLOGW("The inputParams not exist in the subscribeCacheMap_, treat as already unsubscribed.");
        }
        return RUN_OK;
    }
    auto &cacheData = iter->second;
    if (cacheData.callerFullTokenId != IPCSkeleton::GetCallingFullTokenID()) {
        ZLOGE("The caller is not the origin subscriber of the params, can not remove the callback.");
        return UNSUBSCRIBE_EXCEPTION;
    }
    if (cacheData.callback != nullptr && cacheData.cbDeathRecipient != nullptr) {
        callbackObject = cacheData.callback->AsObject();
        deathRecipient = cacheData.cbDeathRecipient;
    }
    subscribeCacheMap_.erase(iter);
    removed = true;
    ZLOGI("Service RemoveCallback exit.");
    return RUN_OK;
}

int32_t DataFabricAddressServiceImpl::ValidateParams(const DataFabricAddressParams &inputParams,
    NativePreferences::LocationPoint& homePoint, NativePreferences::LocationPoint& companyPoint)
{
    if (inputParams.scenarioType != BusinessScenario::SCENARIO_NAVIGATION_COMMUTE) {
        ZLOGE("The scenario type must be 'SCENARIO_NAVIGATION_COMMUTE' from BusinessScenario enum.");
        return NativePreferences::ABNORMAL_OPERATION_EXCEPTION;
    }

    // The commuting scenario requires only 2 coordinate points
    size_t pointCount = inputParams.locationInfo.points.size();
    if (pointCount != NAVIGATION_REFERENCE_POINTS_MAX_COUNT) {
        ZLOGE("The SCENARIO_NAVIGATION_COMMUTE reference points count must be %{public}zu",
            NAVIGATION_REFERENCE_POINTS_MAX_COUNT);
        return NativePreferences::PARAMETER_EXCEPTION;
    }

    int32_t obtainError = ObtainWgs84ReferencePoints(inputParams.locationInfo, homePoint, companyPoint);
    if (obtainError != NativePreferences::RUN_OK) {
        return obtainError;
    }

    // Home-company distance: too short a distance does not support the navigation service.
    return IsSupportedCommuteDistance(homePoint, companyPoint);
}

int32_t DataFabricAddressServiceImpl::ObtainWgs84ReferencePoints(const ReferenceLocationInfo &referenceInfo,
    NativePreferences::LocationPoint& homePoint, NativePreferences::LocationPoint& companyPoint)
{
    ZLOGI("ObtainWgs84ReferencePoints enter.");
    bool hasHomePoint = false;
    LocationInfo homePointInfo;
    bool hasCompanyPoint = false;
    LocationInfo companyPointInfo;
    for (size_t i = 0; i < referenceInfo.points.size(); i++) {
        LocationInfo locationPointInfo = referenceInfo.points[i];
        LabelType labelType = locationPointInfo.labelType;
        if (labelType == LabelType::HOME) {
            homePointInfo = locationPointInfo;
            hasHomePoint = true;
        } else if (labelType == LabelType::COMPANY) {
            companyPointInfo = locationPointInfo;
            hasCompanyPoint = true;
        }
    }
    if (!hasHomePoint || !hasCompanyPoint) {
        ZLOGE("The input reference points are missing home or company location info.");
        return NativePreferences::PARAMETER_EXCEPTION;
    }

    homePoint = homePointInfo.locationPoint;
    if (homePointInfo.coordinateSystemType == NativePreferences::CoordinateSystemType::GCJ02) {
        ZLOGI("The input home point coordinate system is gcj02.");
        NativePreferences::LocationPoint homePointGcj02 = homePointInfo.locationPoint;
        if (!NavigationCommonUtil::Gcj02ToWgs84(homePointGcj02, homePoint)) {
            ZLOGE("The input home reference point coordinate system transform failed.");
            return NativePreferences::INTERNAL_EXCEPTION;
        }
    }

    companyPoint = companyPointInfo.locationPoint;
    if (companyPointInfo.coordinateSystemType == NativePreferences::CoordinateSystemType::GCJ02) {
        ZLOGI("The input company point coordinate system is gcj02.");
        NativePreferences::LocationPoint companyPointGcj02 = companyPointInfo.locationPoint;
        if (!NavigationCommonUtil::Gcj02ToWgs84(companyPointGcj02, companyPoint)) {
            ZLOGE("The input company reference point coordinate system transform failed.");
            return NativePreferences::INTERNAL_EXCEPTION;
        }
    }
    return NativePreferences::RUN_OK;
}

int32_t DataFabricAddressServiceImpl::IsSupportedCommuteDistance(const NativePreferences::LocationPoint& homePoint,
    const NativePreferences::LocationPoint& companyPoint)
{
    ZLOGI("IsSupportedCommuteDistance enter.");
    // Calculate whether the distance reaches the minimum supported distance
    double distance = 0.0;
    if (!NavigationCommonUtil::GetDistance(homePoint, companyPoint, distance)) {
        ZLOGE("Failed to get distance.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    double minSupportedDistance = DEFAULT_MIN_SUPPORTED_COMMUTE_DISTANCE;
    if (distance < minSupportedDistance) {
        ZLOGE("The distance between home and the company is too short, This operation is not supported.");
        return NativePreferences::ABNORMAL_OPERATION_EXCEPTION;
    }
    return NativePreferences::RUN_OK;
}

void DataFabricAddressServiceImpl::DeathRecipientListener::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    ZLOGI("Recv death notice.");
    auto service = service_.lock();
    if (service == nullptr) {
        ZLOGW("The service has been destroyed.");
        return;
    }
    sptr<IRemoteObject> client = remote.promote();
    if (client == nullptr) {
        ZLOGW("The remote promote is null.");
        return;
    }
    std::vector<sptr<IRemoteObject::DeathRecipient>> toRemove;
    bool needTeardown = false;
    {
        std::lock_guard<std::mutex> lock(service->subscribersMutex_);
        bool ownerRemoved = false;
        auto iter = service->subscribeCacheMap_.begin();
        while (iter != service->subscribeCacheMap_.end()) {
            auto &cacheData = iter->second;
            if (cacheData.callback == nullptr || cacheData.cbDeathRecipient == nullptr) {
                ZLOGW("The cached callback or cbDeathRecipient is null, remove it from cache map.");
                iter = service->subscribeCacheMap_.erase(iter);
                continue;
            }
            if (cacheData.callback->AsObject() == client) {
                ZLOGI("The callback will be remove.");
                ownerRemoved = true;
                toRemove.push_back(cacheData.cbDeathRecipient);
                iter = service->subscribeCacheMap_.erase(iter);
                continue;
            }
            ++iter;
        }
        // The collection must not outlive its only subscriber, otherwise the passive location and the
        // live view callbacks keep running while the reports can never be delivered.
        needTeardown = ownerRemoved && service->subscribeCacheMap_.empty();
    }
    for (auto &deathRecipient : toRemove) {
        client->RemoveDeathRecipient(deathRecipient);
    }
    if (!needTeardown) {
        return;
    }
    // Called outside the cache lock because the navigation manager tears the geofence and locator
    // subscriptions down synchronously.
    int32_t ret = NavigationManager::GetInstance().UnsubscribeNavigationManager();
    if (ret != RUN_OK) {
        ZLOGW("Unsubscribe the navigation manager of the dead subscriber failed, ret:%{public}d", ret);
    }
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS