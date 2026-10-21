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

#ifndef DATA_FABRIC_ADDRESS_SERVICE_IMPL_H
#define DATA_FABRIC_ADDRESS_SERVICE_IMPL_H

#include <list>
#include <map>

#include "data_fabric_address_callback.h"
#include "data_fabric_address_service_stub.h"
#include "feature/feature_system.h"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;
using FeatureSystem = DistributedData::FeatureSystem;

class DataFabricAddressServiceImpl : public DataFabricAddressServiceStub,
    public std::enable_shared_from_this<DataFabricAddressServiceImpl> {
public:
    DataFabricAddressServiceImpl() = default;
    ~DataFabricAddressServiceImpl() = default;
    int32_t Subscribe(const DataFabricAddressParams& inputParams,
        sptr<IDataFabricAddressCallback> callback) override;
    int32_t Unsubscribe(const DataFabricAddressParams& inputParams) override;
private:
    class DeathRecipientListener : public IRemoteObject::DeathRecipient {
    public:
        explicit DeathRecipientListener(
            const std::weak_ptr<DataFabricAddressServiceImpl> &service) : service_(service) {}
        virtual ~DeathRecipientListener() = default;
        virtual void OnRemoteDied(const wptr<IRemoteObject> &object);
    private:
        std::weak_ptr<DataFabricAddressServiceImpl> service_;
    };
    struct SubscribeCacheData {
        sptr<IRemoteObject::DeathRecipient> cbDeathRecipient_ { nullptr };
        sptr<IDataFabricAddressCallback> callback_ { nullptr };
    };
    class DataFabricAddressStatic : public DistributedData::StaticActs {
    public:
        ~DataFabricAddressStatic() override {};
        bool IsAbilityInited();
        int32_t OnSystemAbilityAdded(int32_t systemAbilityId, const std::string &deviceId) override;
        int32_t OnSystemAbilityRemoved(int32_t systemAbilityId, const std::string &deviceId) override;
    private:
        std::atomic<bool> isInited_ { false };
    };
    class Factory {
    public:
        Factory();
        ~Factory();
        bool IsInited();
    private:
        std::shared_ptr<DataFabricAddressStatic> staticActs_;
    };
    static Factory factory_;
    int32_t ValidateParams(const DataFabricAddressParams &inputParams, NativePreferences::LocationPoint& homePoint,
        NativePreferences::LocationPoint& companyPoint);
    bool AddCallback(const DataFabricAddressParams& inputParams, sptr<IDataFabricAddressCallback> callback);
    bool RemoveCallback(const DataFabricAddressParams& inputParams);
    bool ObtainWgs84ReferencePoints(const ReferenceLocationInfo &referenceInfo,
        NativePreferences::LocationPoint& homePoint, NativePreferences::LocationPoint& companyPoint);
    int32_t IsSupportedCommuteDistance(const NativePreferences::LocationPoint& homePoint,
        const NativePreferences::LocationPoint& companyPoint);

    std::mutex subscribersMutex_;
    std::map<DataFabricAddressParams, SubscribeCacheData> subscribeCacheMap_;
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_SERVICE_IMPL_H
