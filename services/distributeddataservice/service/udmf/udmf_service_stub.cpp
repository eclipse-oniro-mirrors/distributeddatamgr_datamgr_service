/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "UdmfServiceStub"

#include "udmf_service_stub.h"
#include "ipc_skeleton.h"
#include "log_print.h"
#include "udmf_types_util.h"

namespace OHOS {
namespace UDMF {
constexpr UdmfServiceStub::Handler
    UdmfServiceStub::HANDLERS[static_cast<uint32_t>(UdmfServiceInterfaceCode::CODE_BUTT)];
int UdmfServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start##code = %{public}u callingPid:%{public}u callingUid:%{public}u.", code, IPCSkeleton::GetCallingPid(),
        IPCSkeleton::GetCallingUid());
    std::u16string myDescripter = UdmfServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        ZLOGE("end##descriptor checked fail,myDescripter = %{public}s,remoteDescripter = %{public}s.",
            Str16ToStr8(myDescripter).c_str(), Str16ToStr8(remoteDescripter).c_str());
        return -1;
    }
    if (static_cast<uint32_t>(UdmfServiceInterfaceCode::CODE_HEAD) > code ||
        code >= static_cast<uint32_t>(UdmfServiceInterfaceCode::CODE_BUTT)) {
        return -1;
    }
    return (this->*HANDLERS[code])(data, reply);
}

int32_t UdmfServiceStub::OnSetData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    CustomOption customOption;
    UnifiedData unifiedData;
    if (!ITypesUtil::Unmarshal(data, customOption, unifiedData)) {
        ZLOGE("Unmarshal customOption or unifiedData failed!");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    customOption.tokenId = token;
    std::string key;
    int32_t status = SetData(customOption, unifiedData, key);
    if (!ITypesUtil::Marshal(reply, status, key)) {
        ZLOGE("Marshal status or key failed, status: %{public}d, key: %{public}s", status, key.c_str());
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        ZLOGE("Unmarshal queryOption failed!");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    UnifiedData unifiedData;
    int32_t status = GetData(query, unifiedData);
    if (!ITypesUtil::Marshal(reply, status, unifiedData)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetBatchData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        ZLOGE("Unmarshal queryOption failed!");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    std::vector<UnifiedData> unifiedDataSet;
    int32_t status = GetBatchData(query, unifiedDataSet);
    if (!ITypesUtil::Marshal(reply, status, unifiedDataSet)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnUpdateData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    QueryOption query;
    UnifiedData unifiedData;
    if (!ITypesUtil::Unmarshal(data, query, unifiedData)) {
        ZLOGE("Unmarshal queryOption or unifiedData failed!");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    int32_t status = UpdateData(query, unifiedData);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnDeleteData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        ZLOGE("Unmarshal queryOption failed!");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    std::vector<UnifiedData> unifiedDataSet;
    int32_t status = DeleteData(query, unifiedDataSet);
    if (!ITypesUtil::Marshal(reply, status, unifiedDataSet)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetSummary(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        ZLOGE("Unmarshal query failed");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    Summary summary;
    int32_t status = GetSummary(query, summary);
    if (!ITypesUtil::Marshal(reply, status, summary)) {
        ZLOGE("Marshal summary failed, key: %{public}s", query.key.c_str());
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnAddPrivilege(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    QueryOption query;
    Privilege privilege;
    if (!ITypesUtil::Unmarshal(data, query, privilege)) {
        ZLOGE("Unmarshal query and privilege failed");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    int32_t status = AddPrivilege(query, privilege);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal status failed, key: %{public}s", query.key.c_str());
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnSync(MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start");
    QueryOption query;
    std::vector<std::string> devices;
    if (!ITypesUtil::Unmarshal(data, query, devices)) {
        ZLOGE("Unmarshal query and devices failed");
        return E_READ_PARCEL_ERROR;
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    int32_t status = Sync(query, devices);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal status failed, key: %{public}s", query.key.c_str());
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnIsRemoteData(MessageParcel &data, MessageParcel &reply)
{
    QueryOption query;
    if (!ITypesUtil::Unmarshal(data, query)) {
        ZLOGE("Unmarshal query failed");
        return E_READ_PARCEL_ERROR;
    }
    bool result = false;
    int32_t status = IsRemoteData(query, result);
    if (!ITypesUtil::Marshal(reply, status, result)) {
        ZLOGE("Marshal IsRemoteData result failed, key: %{public}s", query.key.c_str());
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnSetAppShareOption(MessageParcel &data, MessageParcel &reply)
{
    std::string intention;
    int32_t shareOption;
    if (!ITypesUtil::Unmarshal(data, intention, shareOption)) {
        ZLOGE("Unmarshal query failed");
        return E_READ_PARCEL_ERROR;
    }
    int32_t status = SetAppShareOption(intention, shareOption);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetAppShareOption(MessageParcel &data, MessageParcel &reply)
{
    std::string intention;
    int32_t shareOption = SHARE_OPTIONS_BUTT;
    if (!ITypesUtil::Unmarshal(data, intention)) {
        ZLOGE("Unmarshal query failed");
        return E_READ_PARCEL_ERROR;
    }
    int32_t status = GetAppShareOption(intention, shareOption);
    if (!ITypesUtil::Marshal(reply, status, shareOption)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnRemoveAppShareOption(MessageParcel &data, MessageParcel &reply)
{
    std::string intention;
    if (!ITypesUtil::Unmarshal(data, intention)) {
        ZLOGE("Unmarshal query failed");
        return E_READ_PARCEL_ERROR;
    }
    int32_t status = RemoveAppShareOption(intention);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnObtainAsynProcess(MessageParcel &data, MessageParcel &reply)
{
    ZLOGD("start");
    AsyncProcessInfo processInfo;
    if (!ITypesUtil::Unmarshal(data, processInfo)) {
        ZLOGE("Unmarshal processInfo failed");
        return E_READ_PARCEL_ERROR;
    }
    int32_t status = ObtainAsynProcess(processInfo);
    if (!ITypesUtil::Marshal(reply, status, processInfo)) {
        ZLOGE("Marshal status or processInfo failed, status: %{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnClearAsynProcessByKey(MessageParcel &data, MessageParcel &reply)
{
    ZLOGD("start");
    std::string businessUdKey;
    if (!ITypesUtil::Unmarshal(data, businessUdKey)) {
        ZLOGE("Unmarshal businessUdKey failed!");
        return E_READ_PARCEL_ERROR;
    }
    int32_t status = ClearAsynProcessByKey(businessUdKey);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnSetDelayInfo(MessageParcel &data, MessageParcel &reply)
{
    ZLOGD("start");
    DataLoadInfo dataLoadInfo;
    sptr<IRemoteObject> iUdmfNotifier;

    if (!ITypesUtil::Unmarshal(data, dataLoadInfo, iUdmfNotifier)) {
        ZLOGE("Unmarshal failed!");
        return E_READ_PARCEL_ERROR;
    }
    std::string key;
    int32_t status = SetDelayInfo(dataLoadInfo, iUdmfNotifier, key);
    if (!ITypesUtil::Marshal(reply, status, key)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnPushDelayData(MessageParcel &data, MessageParcel &reply)
{
    ZLOGD("start");
    std::string key;
    UnifiedData unifiedData;

    if (!ITypesUtil::Unmarshal(data, key, unifiedData)) {
        ZLOGE("Unmarshal failed!");
        return E_READ_PARCEL_ERROR;
    }

    int32_t status = PushDelayData(key, unifiedData);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}

int32_t UdmfServiceStub::OnGetDataIfAvailable(MessageParcel &data, MessageParcel &reply)
{
    ZLOGD("start");
    std::string key;
    DataLoadInfo dataLoadInfo;
    sptr<IRemoteObject> iUdmfNotifier;
    if (!ITypesUtil::Unmarshal(data, key, dataLoadInfo, iUdmfNotifier)) {
        ZLOGE("Unmarshal failed!");
        return E_READ_PARCEL_ERROR;
    }
    auto unifiedData = std::make_shared<UnifiedData>();
    int32_t status = GetDataIfAvailable(key, dataLoadInfo, iUdmfNotifier, unifiedData);
    if (unifiedData == nullptr) {
        ZLOGE("Data is null, key:%{public}s", key.c_str());
        return E_ERROR;
    }
    if (!ITypesUtil::Marshal(reply, status, *unifiedData)) {
        ZLOGE("Marshal failed:%{public}d", status);
        return E_WRITE_PARCEL_ERROR;
    }
    return E_OK;
}
} // namespace UDMF
} // namespace OHOS