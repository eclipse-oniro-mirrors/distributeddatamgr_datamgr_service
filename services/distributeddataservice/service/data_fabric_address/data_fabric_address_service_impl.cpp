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

#include "data_fabric_address_errors.h"
#include "data_fabric_address_types.h"
#include "log_print.h"
#include "navigation_common_utils.h"
#include "navigation_manager.h"
#include "system_ability_definition.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressServiceImpl"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;
// Minimum supported commuting distance
constexpr double MIN_SUPPORTED_COMMUTE_DISTANCE = 1000.0;
constexpr size_t NAVIGATION_REFERENCE_POINTS_MAX_COUNT {2};

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
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    if (!factory_.IsInited()) {
        ZLOGE("System ability not initialized.");
        return INTERNAL_EXCEPTION;
    }
    NativePreferences::LocationPoint homePoint;
    NativePreferences::LocationPoint companyPoint;
    int32_t ret = ValidateParams(inputParams, homePoint, companyPoint);
    if (ret != RUN_OK) {
        return ret;
    }
    if (!AddCallback(inputParams, callback)) {
        return INTERNAL_EXCEPTION;
    }
    ActionType actionType = inputParams.locationInfo.actionType;
    return NavigationManager::GetInstance().SubscribeNavigationManager(actionType, homePoint, companyPoint, callback);
}

bool DataFabricAddressServiceImpl::AddCallback(const DataFabricAddressParams& inputParams,
    sptr<IDataFabricAddressCallback> callback)
{
    ZLOGI("Service AddCallback enter.");
    if (inputParams.locationInfo.actionType == ActionType::UPDATE) {
        ZLOGI("The update action do not need to add callback.");
        return true;
    }
    auto object = callback->AsObject();
    sptr<DeathRecipientListener> cbDeathRecipient = new (std::nothrow) DeathRecipientListener(weak_from_this());
    if (cbDeathRecipient == nullptr) {
        ZLOGE("Failed to create cbDeathRecipient.");
        return false;
    }
    object->AddDeathRecipient(cbDeathRecipient);
    subscribeCacheMap_.emplace(inputParams, SubscribeCacheData{cbDeathRecipient, callback});
    ZLOGI("Service AddCallback exit.");
    return true;
}

int32_t DataFabricAddressServiceImpl::Unsubscribe(const DataFabricAddressParams& inputParams)
{
    ZLOGI("Service Unsubscribe enter.");
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    if (!factory_.IsInited()) {
        ZLOGE("System ability not initialized.");
        return INTERNAL_EXCEPTION;
    }
    if (!RemoveCallback(inputParams)) {
        return INTERNAL_EXCEPTION;
    }
    return NavigationManager::GetInstance().UnsubscribeNavigationManager();
}

bool DataFabricAddressServiceImpl::RemoveCallback(const DataFabricAddressParams& inputParams)
{
    ZLOGI("Service RemoveCallback enter.");
    const auto iter = subscribeCacheMap_.find(inputParams);
    if (iter == subscribeCacheMap_.end()) {
        ZLOGI("The inputParams not exist in the subscribeCacheMap_, do not need to remove.");
        return true;
    }
    auto &cacheData = iter->second;
    cacheData.callback_->AsObject()->RemoveDeathRecipient(cacheData.cbDeathRecipient_);
    subscribeCacheMap_.erase(iter);
    ZLOGI("Service RemoveCallback exit.");
    return true;
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

    if (!ObtainWgs84ReferencePoints(inputParams.locationInfo, homePoint, companyPoint)) {
        ZLOGE("Obtain wgs84 reference points failed.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }

    // Home-company distance: too short a distance does not support the navigation service.
    return IsSupportedCommuteDistance(homePoint, companyPoint);
}

bool DataFabricAddressServiceImpl::ObtainWgs84ReferencePoints(const ReferenceLocationInfo &referenceInfo,
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
        return false;
    }

    homePoint = homePointInfo.locationPoint;
    if (homePointInfo.coordinateSystemType == NativePreferences::CoordinateSystemType::GCJ02) {
        ZLOGI("The input home point coordinate system is gcj02.");
        NativePreferences::LocationPoint homePointGcj02 = homePointInfo.locationPoint;
        if (!NavigationCommonUtil::Gcj02ToWgs84(homePointGcj02, homePoint)) {
            ZLOGE("The input home reference point coordinate system transform failed.");
            return false;
        }
    }

    companyPoint = companyPointInfo.locationPoint;
    if (companyPointInfo.coordinateSystemType == NativePreferences::CoordinateSystemType::GCJ02) {
        ZLOGI("The input company point coordinate system is gcj02.");
        NativePreferences::LocationPoint companyPointGcj02 = companyPointInfo.locationPoint;
        if (!NavigationCommonUtil::Gcj02ToWgs84(companyPointGcj02, companyPoint)) {
            ZLOGE("The input company reference point coordinate system transform failed.");
            return false;
        }
    }
    return true;
}

int32_t DataFabricAddressServiceImpl::IsSupportedCommuteDistance(const NativePreferences::LocationPoint& homePoint,
    const NativePreferences::LocationPoint& companyPoint)
{
    ZLOGI("IsSupportedCommuteDistance enter.");
    // Calculate whether the distance is less than 1000 m
    double distance = 0.0;
    if (!NavigationCommonUtil::GetDistance(homePoint, companyPoint, distance)) {
        ZLOGE("Failed to get distance.");
        return NativePreferences::INTERNAL_EXCEPTION;
    }
    ZLOGI("The distance between home and the company is %{public}f", distance);
    if (distance < MIN_SUPPORTED_COMMUTE_DISTANCE) {
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
    std::lock_guard<std::mutex> lock(service->subscribersMutex_);
    sptr<IRemoteObject> client = remote.promote();
    if (client == nullptr) {
        ZLOGW("The remote promote is null.");
        return;
    }
    auto iter = service->subscribeCacheMap_.begin();
    while (iter != service->subscribeCacheMap_.end()) {
        auto &cacheData = iter->second;
        if (cacheData.callback_ == nullptr || cacheData.cbDeathRecipient_ == nullptr) {
            ZLOGW("The cached callback_ or cbDeathRecipient_ is null, remove it from cache map.");
            iter = service->subscribeCacheMap_.erase(iter);
            continue;
        }
        if (cacheData.callback_->AsObject() == client) {
            ZLOGI("The callback will be remove.");
            cacheData.callback_->AsObject()->RemoveDeathRecipient(cacheData.cbDeathRecipient_);
            iter = service->subscribeCacheMap_.erase(iter);
            continue;
        }
        ++iter;
    }
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS