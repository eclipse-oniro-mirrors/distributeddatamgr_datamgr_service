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

#ifndef DATA_FABRIC_ADDRESS_SERVICE_STUB_H
#define DATA_FABRIC_ADDRESS_SERVICE_STUB_H

#include "feature/feature_system.h"
#include "data_fabric_address_types.h"
#include "i_data_fabric_address.h"
#include "iremote_proxy.h"

namespace OHOS {
namespace DataFabricAddress {
using namespace NativePreferences;

class IDataFabricAddressService {
public:
    enum RemoteOperation {
        SUBSCRIBE,
        UNSUBSCRIBE,
    };
    virtual int32_t Subscribe(const DataFabricAddressParams& inputParams,
        sptr<IDataFabricAddressCallback> callback) = 0;
    virtual int32_t Unsubscribe(const DataFabricAddressParams& inputParams) = 0;
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.DataFabricAddress.IDataFabricAddressService");
};

class DataFabricAddressServiceStub : public DataFabricAddress::IDataFabricAddressService,
    public DistributedData::FeatureSystem::Feature {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);

private:
    enum DataFabricAddressCmdCode : int32_t {
        DATA_FABRIC_ADDRESS_CMD_SUBSCRIBE,
        DATA_FABRIC_ADDRESS_CMD_UNSUBSCRIBE,
        DATA_FABRIC_ADDRESS_CMD_MAX,
    };
    int32_t OnSubscribe(MessageParcel &data, MessageParcel &reply);
    int32_t OnUnsubscribe(MessageParcel &data, MessageParcel &reply);
    bool IsSystemApp();
    bool CheckPermission();
    bool IsTargetsDeviceTypes();
    int32_t CheckValidCall();
    using Handler = int32_t (DataFabricAddressServiceStub::*)(MessageParcel &data, MessageParcel &reply);
    static const Handler handlers[DataFabricAddressCmdCode::DATA_FABRIC_ADDRESS_CMD_MAX];
};
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_SERVICE_STUB_H
