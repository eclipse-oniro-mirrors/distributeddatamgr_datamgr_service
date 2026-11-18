/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <fuzzer/FuzzedDataProvider.h>

#include "datashareserviceimpl3_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "data_share_service_impl.h"

using namespace OHOS::DataShare;

namespace OHOS {
// Semantic proxy URI pool: datashareproxy:// scheme is the only legal scheme of
// proxy data, and uris with/without query parameters drive the query-parameter
// parsing branches of proxy data strategies.
constexpr const char *PROXY_URI_POOL[] = {
    "datashareproxy://com.example.provider/dataKey",
    "datashareproxy://com.ohos.settingsdata/setting",
    "datashareproxy://com.example.provider/store/table",
};
constexpr size_t PROXY_URI_POOL_SIZE = sizeof(PROXY_URI_POOL) / sizeof(PROXY_URI_POOL[0]);

// Invalid value of DataProxyMaxValueLength, drives the invalid branch of
// DataShareServiceImpl::GetProxyData.
constexpr int32_t INVALID_MAX_VALUE_LENGTH = 500;

// Target interface count of this fuzzer, used by the entry switch.
constexpr size_t TARGET_SIZE = 9;

std::string ConsumeProxyUriFromPool(FuzzedDataProvider &fdp)
{
    return PROXY_URI_POOL[fdp.ConsumeIntegral<uint8_t>() % PROXY_URI_POOL_SIZE];
}

// Enum-sized switch with uint8_t index: 0 -> MAX_LENGTH_4K, 1 -> MAX_LENGTH_100K,
// others -> invalid value, so every branch of the maxValueLength_ check is hit.
DataProxyConfig MakeProxyConfig(FuzzedDataProvider &fdp)
{
    DataProxyConfig proxyConfig;
    proxyConfig.type_ = DataProxyType::SHARED_CONFIG;
    switch (fdp.ConsumeIntegral<uint8_t>() % 4) {
        case 0:
            proxyConfig.maxValueLength_ = DataProxyMaxValueLength::MAX_LENGTH_4K;
            break;
        case 1:
            proxyConfig.maxValueLength_ = DataProxyMaxValueLength::MAX_LENGTH_100K;
            break;
        default:
            proxyConfig.maxValueLength_ = static_cast<DataProxyMaxValueLength>(INVALID_MAX_VALUE_LENGTH);
            break;
    }
    return proxyConfig;
}

// Builds all four variant alternatives of DataProxyValue.
DataProxyValue MakeProxyValue(FuzzedDataProvider &fdp)
{
    switch (fdp.ConsumeIntegral<uint8_t>() % 4) {
        case 0:
            return fdp.ConsumeIntegral<int64_t>();
        case 1:
            return fdp.ConsumeFloatingPoint<double>();
        case 2:
            return fdp.ConsumeRandomLengthString(64);
        default:
            return fdp.ConsumeBool();
    }
}

void PublishProxyDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<DataShareProxyData> proxyDatas;
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % 3; // 0-2 proxy datas
    for (uint8_t i = 0; i < count; i++) {
        DataShareProxyData proxyData(ConsumeProxyUriFromPool(fdp), MakeProxyValue(fdp));
        // isMultiValues_ drives the PUBLISH_MULTIVALUES / NORMAL_PUBLISH branch.
        proxyData.isMultiValues_ = fdp.ConsumeBool();
        uint8_t allowListSize = fdp.ConsumeIntegral<uint8_t>() % 3; // 0-2 allow list items
        for (uint8_t j = 0; j < allowListSize; j++) {
            proxyData.allowList_.push_back(fdp.ConsumeRandomLengthString(64));
        }
        proxyDatas.push_back(std::move(proxyData));
    }
    DataProxyConfig proxyConfig = MakeProxyConfig(fdp);
    dataShareServiceImpl->PublishProxyData(proxyDatas, proxyConfig);
}

void DeleteProxyDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris;
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % 3; // 0-2 uris
    for (uint8_t i = 0; i < count; i++) {
        uris.push_back(ConsumeProxyUriFromPool(fdp));
    }
    DataProxyConfig proxyConfig = MakeProxyConfig(fdp);
    dataShareServiceImpl->DeleteProxyData(uris, proxyConfig);
}

void DeleteAllProxyDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    DataProxyConfig proxyConfig = MakeProxyConfig(fdp);
    dataShareServiceImpl->DeleteAllProxyData(proxyConfig);
}

void GetProxyDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris;
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % 3; // 0-2 uris
    for (uint8_t i = 0; i < count; i++) {
        uris.push_back(ConsumeProxyUriFromPool(fdp));
    }
    DataProxyConfig proxyConfig = MakeProxyConfig(fdp);
    dataShareServiceImpl->GetProxyData(uris, proxyConfig);
}

void SubscribeProxyDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris;
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % 3; // 0-2 uris
    for (uint8_t i = 0; i < count; i++) {
        uris.push_back(ConsumeProxyUriFromPool(fdp));
    }
    sptr<IProxyDataObserver> observer;
    dataShareServiceImpl->SubscribeProxyData(uris, observer);
}

void UnsubscribeProxyDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris;
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % 3; // 0-2 uris
    for (uint8_t i = 0; i < count; i++) {
        uris.push_back(ConsumeProxyUriFromPool(fdp));
    }
    dataShareServiceImpl->UnsubscribeProxyData(uris);
}

void PutValueFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeProxyUriFromPool(fdp);
    std::string key = fdp.ConsumeRandomLengthString(64);
    DataProxyValue value = MakeProxyValue(fdp);
    DataProxyConfig proxyConfig = MakeProxyConfig(fdp);
    dataShareServiceImpl->PutValue(uri, key, value, proxyConfig);
}

void RemoveValueFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeProxyUriFromPool(fdp);
    std::string key = fdp.ConsumeRandomLengthString(64);
    DataProxyConfig proxyConfig = MakeProxyConfig(fdp);
    dataShareServiceImpl->RemoveValue(uri, key, proxyConfig);
}

void GetValuesFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeProxyUriFromPool(fdp);
    DataProxyConfig proxyConfig = MakeProxyConfig(fdp);
    dataShareServiceImpl->GetValues(uri, proxyConfig);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    uint8_t target = fdp.ConsumeIntegral<uint8_t>() % OHOS::TARGET_SIZE;
    switch (target) {
        case 0:
            OHOS::PublishProxyDataFuzz(fdp);
            break;
        case 1:
            OHOS::DeleteProxyDataFuzz(fdp);
            break;
        case 2:
            OHOS::DeleteAllProxyDataFuzz(fdp);
            break;
        case 3:
            OHOS::GetProxyDataFuzz(fdp);
            break;
        case 4:
            OHOS::SubscribeProxyDataFuzz(fdp);
            break;
        case 5:
            OHOS::UnsubscribeProxyDataFuzz(fdp);
            break;
        case 6:
            OHOS::PutValueFuzz(fdp);
            break;
        case 7:
            OHOS::RemoveValueFuzz(fdp);
            break;
        default:
            OHOS::GetValuesFuzz(fdp);
            break;
    }
    return 0;
}
