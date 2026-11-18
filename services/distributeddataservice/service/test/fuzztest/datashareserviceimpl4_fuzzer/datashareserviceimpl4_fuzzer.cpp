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

#include "datashareserviceimpl4_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "data_share_service_impl.h"

using namespace OHOS::DataShare;

namespace OHOS {
// Semantic URI pool of RDB/published subscription. The same pool is used to
// build the SubscribeOption.subscribeStatus map, so both the find-hit branch
// and the missed-status branch of SubscribeRdbData are covered.
constexpr const char *SUB_URI_POOL[] = {
    "datashare://com.example.provider/module/store/table",
    "datashareproxy://com.example.provider/dataKey",
};
constexpr size_t SUB_URI_POOL_SIZE = sizeof(SUB_URI_POOL) / sizeof(SUB_URI_POOL[0]);

// URI that never appears in SUB_URI_POOL, used to trigger the missed-status
// branch of SubscribeRdbData.
constexpr const char *MISSED_STATUS_URI = "datashare://com.example.missed/dataKey";

// Upper bound of consumed random-length strings, keeps a single input cheap.
constexpr size_t MAX_TEXT_LENGTH = 64;
// Max uri count consumed by the uri-list driven fuzz functions.
constexpr uint8_t MAX_URI_COUNT = 3;
// Max published data item count consumed by PublishFuzz.
constexpr uint8_t MAX_PUBLISHED_ITEM_COUNT = 3;

// Dispatch targets of the entry switch, indexed by the first consumed byte.
enum FuzzTarget : uint8_t {
    FUZZ_PUBLISH = 0,
    FUZZ_SUBSCRIBE_RDB_DATA,
    FUZZ_UNSUBSCRIBE_RDB_DATA,
    FUZZ_ENABLE_RDB_SUBS,
    FUZZ_DISABLE_RDB_SUBS,
    FUZZ_SUBSCRIBE_PUBLISHED_DATA,
    FUZZ_UNSUBSCRIBE_PUBLISHED_DATA,
    FUZZ_ENABLE_PUB_SUBS,
    FUZZ_DISABLE_PUB_SUBS,
};

// Target interface count of this fuzzer, used by the entry switch.
constexpr size_t TARGET_SIZE = 9;

std::vector<std::string> ConsumeSubUris(FuzzedDataProvider &fdp)
{
    std::vector<std::string> uris;
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % MAX_URI_COUNT;
    for (uint8_t i = 0; i < count; i++) {
        uris.push_back(SUB_URI_POOL[fdp.ConsumeIntegral<uint8_t>() % SUB_URI_POOL_SIZE]);
    }
    return uris;
}

TemplateId MakeTemplateId(FuzzedDataProvider &fdp)
{
    TemplateId id;
    id.subscriberId_ = fdp.ConsumeIntegral<int64_t>();
    id.bundleName_ = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    return id;
}

// Builds a non-empty subscribeStatus map: the first entry hits the subscribed
// uri and the second one never hits, covering all three branches
// (empty / find-hit / missed) of SubscribeRdbData.
SubscribeOption MakeSubscribeOption(FuzzedDataProvider &fdp, const std::vector<std::string> &uris)
{
    SubscribeOption option;
    if (!uris.empty()) {
        option.subscribeStatus[uris[0]] = fdp.ConsumeBool();
    }
    option.subscribeStatus[MISSED_STATUS_URI] = fdp.ConsumeBool();
    return option;
}

void PublishFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    Data data;
    data.version_ = fdp.ConsumeIntegral<int32_t>();
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % MAX_PUBLISHED_ITEM_COUNT;
    for (uint8_t i = 0; i < count; i++) {
        std::string key = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
        int64_t subscriberId = fdp.ConsumeIntegral<int64_t>();
        std::string value = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
        data.datas_.emplace_back(key, subscriberId, value);
    }
    std::string bundleNameOfProvider = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    dataShareServiceImpl->Publish(data, bundleNameOfProvider);
}

void SubscribeRdbDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    TemplateId id = MakeTemplateId(fdp);
    sptr<IDataProxyRdbObserver> observer;
    SubscribeOption option = MakeSubscribeOption(fdp, uris);
    dataShareServiceImpl->SubscribeRdbData(uris, id, observer, option);
}

void UnsubscribeRdbDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    TemplateId id = MakeTemplateId(fdp);
    dataShareServiceImpl->UnsubscribeRdbData(uris, id);
}

void EnableRdbSubsFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    TemplateId id = MakeTemplateId(fdp);
    dataShareServiceImpl->EnableRdbSubs(uris, id);
}

void DisableRdbSubsFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    TemplateId id = MakeTemplateId(fdp);
    dataShareServiceImpl->DisableRdbSubs(uris, id);
}

void SubscribePublishedDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    int64_t subscriberId = fdp.ConsumeIntegral<int64_t>();
    sptr<IDataProxyPublishedDataObserver> observer;
    dataShareServiceImpl->SubscribePublishedData(uris, subscriberId, observer);
}

void UnsubscribePublishedDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    int64_t subscriberId = fdp.ConsumeIntegral<int64_t>();
    dataShareServiceImpl->UnsubscribePublishedData(uris, subscriberId);
}

void EnablePubSubsFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    int64_t subscriberId = fdp.ConsumeIntegral<int64_t>();
    dataShareServiceImpl->EnablePubSubs(uris, subscriberId);
}

void DisablePubSubsFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::vector<std::string> uris = ConsumeSubUris(fdp);
    int64_t subscriberId = fdp.ConsumeIntegral<int64_t>();
    dataShareServiceImpl->DisablePubSubs(uris, subscriberId);
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
        case OHOS::FUZZ_PUBLISH:
            OHOS::PublishFuzz(fdp);
            break;
        case OHOS::FUZZ_SUBSCRIBE_RDB_DATA:
            OHOS::SubscribeRdbDataFuzz(fdp);
            break;
        case OHOS::FUZZ_UNSUBSCRIBE_RDB_DATA:
            OHOS::UnsubscribeRdbDataFuzz(fdp);
            break;
        case OHOS::FUZZ_ENABLE_RDB_SUBS:
            OHOS::EnableRdbSubsFuzz(fdp);
            break;
        case OHOS::FUZZ_DISABLE_RDB_SUBS:
            OHOS::DisableRdbSubsFuzz(fdp);
            break;
        case OHOS::FUZZ_SUBSCRIBE_PUBLISHED_DATA:
            OHOS::SubscribePublishedDataFuzz(fdp);
            break;
        case OHOS::FUZZ_UNSUBSCRIBE_PUBLISHED_DATA:
            OHOS::UnsubscribePublishedDataFuzz(fdp);
            break;
        case OHOS::FUZZ_ENABLE_PUB_SUBS:
            OHOS::EnablePubSubsFuzz(fdp);
            break;
        default:
            OHOS::DisablePubSubsFuzz(fdp);
            break;
    }
    return 0;
}
