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

#include <vector>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "log_print.h"
#include "udmf_types_util.h"
#include "unified_data.h"
#include "unified_meta.h"

namespace OHOS {
namespace UDMF {
constexpr UdmfServiceStub::Handler
    UdmfServiceStub::HANDLERS[static_cast<uint32_t>(UdmfServiceInterfaceCode::CODE_BUTT)];
int UdmfServiceStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    ZLOGI("start##code = %{public}u", code);
    std::u16string myDescripter = UdmfServiceStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (myDescripter != remoteDescripter) {
        ZLOGE("end##descriptor checked fail");
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
    if (unifiedData.IsEmpty()) {
        ZLOGE("Empty data without any record!");
        return E_INVALID_PARAMETERS;
    }
    if (unifiedData.GetSize() > UdmfService::MAX_DATA_SIZE) {
        ZLOGE("Exceeded data limit!");
        return E_INVALID_PARAMETERS;
    }
    for (const auto &record : unifiedData.GetRecords()) {
        if (record == nullptr) {
            ZLOGE("record is nullptr!");
            return E_INVALID_PARAMETERS;
        }
        if (record->GetSize() > UdmfService::MAX_RECORD_SIZE) {
            ZLOGE("Exceeded record limit!");
            return E_INVALID_PARAMETERS;
        }
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
        ZLOGE("Marshal status or unifiedData failed, status: %{public}d", status);
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
        ZLOGE("Marshal status or unifiedDataSet failed, status: %{public}d", status);
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
    if (unifiedData.IsEmpty()) {
        ZLOGE("Empty data without any record!");
        return E_INVALID_PARAMETERS;
    }
    if (unifiedData.GetSize() > UdmfService::MAX_DATA_SIZE) {
        ZLOGE("Exceeded data limit!");
        return E_INVALID_PARAMETERS;
    }
    for (const auto &record : unifiedData.GetRecords()) {
        if (record->GetSize() > UdmfService::MAX_RECORD_SIZE) {
            ZLOGE("Exceeded record limit!");
            return E_INVALID_PARAMETERS;
        }
    }
    uint32_t token = static_cast<uint32_t>(IPCSkeleton::GetCallingTokenID());
    query.tokenId = token;
    int32_t status = UpdateData(query, unifiedData);
    if (!ITypesUtil::Marshal(reply, status)) {
        ZLOGE("Marshal status failed, status: %{public}d", status);
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
        ZLOGE("Marshal status or unifiedDataSet failed, status: %{public}d", status);
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

/*
 * Check whether the caller has the permission to access data.
 */
bool UdmfServiceStub::VerifyPermission(const std::string &permission)
{
#ifdef UDMF_PERMISSION_ENABLED
    uint32_t tokenId = IPCSkeleton::GetCallingTokenID();
    int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(tokenId, permission);
    return result == Security::AccessToken::TypePermissionState::PERMISSION_GRANTED;
#else
    return true;
#endif // UDMF_PERMISSION_ENABLED
}
} // namespace UDMF
} // namespace OHOS