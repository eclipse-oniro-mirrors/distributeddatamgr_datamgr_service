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

#include "data_fabric_address_service_stub.h"

#include "accesstoken_kit.h"
#include "data_fabric_address_callback.h"
#include "data_fabric_address_callback_proxy.h"
#include "data_fabric_address_errors.h"
#include "data_fabric_address_types_util.h"
#include "ipc_skeleton.h"
#include "itypes_util.h"
#include "log_print.h"
#include "parameters.h"
#include "string_ex.h"
#include "tokenid_kit.h"

#undef LOG_TAG
#define LOG_TAG "DataFabricAddressServiceStub"

namespace OHOS {
namespace DataFabricAddress {
using namespace DistributedData;
const std::string LOCATION_IN_BACKGROUND = "ohos.permission.LOCATION_IN_BACKGROUND";
const std::string LOCATION = "ohos.permission.LOCATION";
const std::string APPROXIMATELY_LOCATION = "ohos.permission.APPROXIMATELY_LOCATION";
const DataFabricAddressServiceStub::Handler DataFabricAddressServiceStub::handlers[
    DataFabricAddressCmdCode::DATA_FABRIC_ADDRESS_CMD_MAX] = {
    &DataFabricAddressServiceStub::OnSubscribe,
    &DataFabricAddressServiceStub::OnUnsubscribe,
};

int DataFabricAddressServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    std::u16string localDescriptor = DataFabricAddressServiceStub::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (localDescriptor != remoteDescriptor) {
        ZLOGE("The descriptor check mismatched, localDescriptor:%{public}s, remoteDescriptor:%{public}s",
            Str16ToStr8(localDescriptor).c_str(), Str16ToStr8(remoteDescriptor).c_str());
        return INTERNAL_EXCEPTION;
    }

    if (code < DATA_FABRIC_ADDRESS_CMD_SUBSCRIBE || code >= DATA_FABRIC_ADDRESS_CMD_MAX) {
        ZLOGE("The cmd code is out of enum! code:%{public}u", code);
        return INTERNAL_EXCEPTION;
    }

    int32_t ret = CheckValidCall();
    if (ret != RUN_OK) {
        reply.WriteInt32(ret);
        return ret;
    }

    return (this->*handlers[code])(data, reply);
}

int32_t DataFabricAddressServiceStub::OnSubscribe(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("OnSubscribe enter.");
    DataFabricAddressParams inputParams;
    if (!ITypesUtil::Unmarshal(data, inputParams)) {
        ZLOGE("Unmarshal params failed.");
        reply.WriteInt32(INTERNAL_EXCEPTION);
        return INTERNAL_EXCEPTION;
    }

    sptr<IRemoteObject> callbackRemote = data.ReadRemoteObject();
    if (callbackRemote == nullptr) {
        ZLOGE("The callback remote is null.");
        reply.WriteInt32(INTERNAL_EXCEPTION);
        return INTERNAL_EXCEPTION;
    }

    sptr<IDataFabricAddressCallback> callback = new (std::nothrow) DataFabricAddressCallbackProxy(callbackRemote);
    if (callback == nullptr) {
        ZLOGE("The callback cast failed.");
        reply.WriteInt32(INTERNAL_EXCEPTION);
        return INTERNAL_EXCEPTION;
    }

    int32_t status = Subscribe(inputParams, callback);
    ZLOGI("OnSubscribe Subscribe result status=%{public}d.", status);
    if (!reply.WriteInt32(status)) {
        ZLOGE("Write OnSubscribe result code error.");
        return INTERNAL_EXCEPTION;
    }
    ZLOGI("OnSubscribe exit.");
    return RUN_OK;
}

int32_t DataFabricAddressServiceStub::OnUnsubscribe(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("OnUnsubscribe enter.");
    DataFabricAddressParams inputParams;
    if (!ITypesUtil::Unmarshal(data, inputParams)) {
        ZLOGE("Unmarshal params failed.");
        reply.WriteInt32(INTERNAL_EXCEPTION);
        return INTERNAL_EXCEPTION;
    }

    int32_t status = Unsubscribe(inputParams);
    ZLOGI("OnUnsubscribe Unsubscribe result status=%{public}d.", status);
    if (!reply.WriteInt32(status)) {
        ZLOGE("Write OnUnsubscribe result code error.");
        return INTERNAL_EXCEPTION;
    }
    ZLOGI("OnUnsubscribe exit.");
    return RUN_OK;
}

int32_t DataFabricAddressServiceStub::CheckValidCall()
{
    if (!IsSystemApp()) {
        ZLOGE("Not system app.");
        return NOT_SYSTEM_CALL;
    }
    if (!CheckPermission()) {
        ZLOGE("No permissions.");
        return PERMISSION_EXCEPTION;
    }
    if (!IsTargetsDeviceTypes()) {
        ZLOGE("Not target device type.");
        return DEVICE_EXCEPTION;
    }
    return RUN_OK;
}

bool DataFabricAddressServiceStub::IsSystemApp()
{
    auto callerToken = IPCSkeleton::GetCallingTokenID();
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(callerToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE ||
        tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_SHELL) {
        return true;
    } else if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        uint64_t accessTokenIDEx = IPCSkeleton::GetCallingFullTokenID();
        return Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(accessTokenIDEx);
    }
    ZLOGE("Illegal tokenType: %{public}d", tokenType);
    return false;
}

bool DataFabricAddressServiceStub::IsTargetsDeviceTypes()
{
    std::string deviceType = OHOS::system::GetParameter("const.product.devicetype", "");
    ZLOGI("Current deviceType: %{public}s", deviceType.c_str());
    return deviceType == "phone";
}

bool DataFabricAddressServiceStub::CheckPermission()
{
    ZLOGI("Service CheckPermission enter.");
    Security::AccessToken::AccessTokenID tokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, APPROXIMATELY_LOCATION);
    if (ret != Security::AccessToken::PERMISSION_GRANTED) {
        ZLOGE("Not granted %{public}s", APPROXIMATELY_LOCATION.c_str());
        return false;
    }
    ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, LOCATION);
    if (ret != Security::AccessToken::PERMISSION_GRANTED) {
        ZLOGE("Not granted %{public}s", LOCATION.c_str());
        return false;
    }
    ret = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, LOCATION_IN_BACKGROUND);
    if (ret != Security::AccessToken::PERMISSION_GRANTED) {
        ZLOGE("Not granted %{public}s", LOCATION_IN_BACKGROUND.c_str());
        return false;
    }
    ZLOGI("Service CheckPermission exit.");
    return true;
}
} // End of namespace DataFabricAddress
} // End of namespace OHOS