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

#include "datashareserviceimpl2_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "data_share_service_impl.h"
#include "ipc_skeleton.h"

using namespace OHOS::DataShare;

namespace OHOS {
// Semantic URI pool: drives the URI parsing branches of DataShareServiceImpl,
// including the four-segment path check in URIUtils::GetInfoFromURI, the
// settings bundle token-id cache in GetCalledTokenId, the proxy schema check
// and the appIndex/accountId query-parameter parsing paths.
constexpr const char *URI_POOL[] = {
    "datashare://com.ohos.settingsdata/settings/settings/settings",
    "datashare://com.example.provider/module/store/table",
    "datashareproxy://com.example.provider/dataKey",
    "datashareproxy://com.example.provider/store/table?appIndex=2&accountId=100",
    "datashareproxy://com.example.provider/store/table?appIndex=abc",
};
constexpr size_t URI_POOL_SIZE = sizeof(URI_POOL) / sizeof(URI_POOL[0]);

// Semantic SQL text pool: drives every branch of VerifyColumns and
// VerifyQueryLanguage, including legal column names that only differ from
// keywords by word boundary (update_time), dangerous keywords (SELECT/FROM/
// JOIN/UNION/DROP), statement separators (';'), comment markers ('--', '/*')
// and keyword splitting (SEL/**/ECT).
constexpr const char *SQL_TEXT_POOL[] = {
    "id",
    "update_time",
    "SELECT",
    "from",
    "JOIN t2 ON t1.id",
    "UNION ALL",
    "DROP TABLE",
    "a;DROP",
    "x--y",
    "/*body*/",
    "SEL/**/ECT",
    "",
};
constexpr size_t SQL_TEXT_POOL_SIZE = sizeof(SQL_TEXT_POOL) / sizeof(SQL_TEXT_POOL[0]);

// Upper bound of consumed random-length strings, keeps a single input cheap.
constexpr size_t MAX_TEXT_LENGTH = 64;
// Alternative count of the value types held by DataShareValuesBucket.
constexpr uint8_t VARIANT_TYPE_COUNT = 4;
// Max column count consumed by QueryFuzz.
constexpr uint8_t MAX_COLUMN_COUNT = 4;
// Max predicate node count of the Template consumed by AddTemplateFuzz.
constexpr uint8_t MAX_PREDICATE_NODE_COUNT = 3;

// Value kinds selected by the variant switch of BuildValuesBucket.
enum ValueKind : uint8_t {
    KIND_INT64 = 0,
    KIND_DOUBLE,
    KIND_STRING,
    KIND_BOOL,
};

// Dispatch targets of the entry switch, indexed by the first consumed byte.
enum FuzzTarget : uint8_t {
    FUZZ_INSERT_EX = 0,
    FUZZ_QUERY,
    FUZZ_UPDATE_EX,
    FUZZ_DELETE_EX,
    FUZZ_ADD_TEMPLATE,
    FUZZ_DEL_TEMPLATE,
    FUZZ_NOTIFY_OBSERVER,
    FUZZ_GET_DATA,
    FUZZ_GET_SILENT_PROXY_STATUS,
    FUZZ_ENABLE_SILENT_PROXY,
};

// Target interface count of this fuzzer, used by the entry switch.
constexpr size_t TARGET_SIZE = 10;

std::string ConsumeUriFromPool(FuzzedDataProvider &fdp)
{
    return URI_POOL[fdp.ConsumeIntegral<uint8_t>() % URI_POOL_SIZE];
}

std::string ConsumeSqlTextFromPool(FuzzedDataProvider &fdp)
{
    return SQL_TEXT_POOL[fdp.ConsumeIntegral<uint8_t>() % SQL_TEXT_POOL_SIZE];
}

// Non-empty whereClause/order switches settingMode_ to QUERY_LANGUAGE, so the
// predicates drive the VerifyQueryLanguage branch of VerifyPredicates.
DataSharePredicates BuildPredicates(FuzzedDataProvider &fdp)
{
    DataSharePredicates predicates;
    predicates.SetWhereClause(ConsumeSqlTextFromPool(fdp));
    predicates.SetOrder(ConsumeSqlTextFromPool(fdp));
    return predicates;
}

// Builds a values bucket with one entry, the value kind is selected by the
// input byte.
DataShareValuesBucket BuildValuesBucket(FuzzedDataProvider &fdp)
{
    DataShareValuesBucket valuesBucket;
    std::string key = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    switch (fdp.ConsumeIntegral<uint8_t>() % VARIANT_TYPE_COUNT) {
        case KIND_INT64:
            valuesBucket.valuesMap[key] = fdp.ConsumeIntegral<int64_t>();
            break;
        case KIND_DOUBLE:
            valuesBucket.valuesMap[key] = fdp.ConsumeFloatingPoint<double>();
            break;
        case KIND_STRING:
            valuesBucket.valuesMap[key] = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
            break;
        default:
            valuesBucket.valuesMap[key] = fdp.ConsumeBool();
            break;
    }
    return valuesBucket;
}

void InsertExFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    std::string extUri = ConsumeUriFromPool(fdp);
    DataShareValuesBucket valuesBucket = BuildValuesBucket(fdp);
    dataShareServiceImpl->InsertEx(uri, extUri, valuesBucket);
}

void QueryFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    std::string extUri = ConsumeUriFromPool(fdp);
    DataSharePredicates predicates = BuildPredicates(fdp);
    std::vector<std::string> columns;
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % MAX_COLUMN_COUNT;
    for (uint8_t i = 0; i < count; i++) {
        columns.push_back(ConsumeSqlTextFromPool(fdp));
    }
    int32_t errCode = 0;
    dataShareServiceImpl->Query(uri, extUri, predicates, columns, errCode);
}

void UpdateExFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    std::string extUri = ConsumeUriFromPool(fdp);
    DataSharePredicates predicates = BuildPredicates(fdp);
    DataShareValuesBucket valuesBucket = BuildValuesBucket(fdp);
    dataShareServiceImpl->UpdateEx(uri, extUri, predicates, valuesBucket);
}

void DeleteExFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    std::string extUri = ConsumeUriFromPool(fdp);
    DataSharePredicates predicates = BuildPredicates(fdp);
    dataShareServiceImpl->DeleteEx(uri, extUri, predicates);
}

void AddTemplateFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    int64_t subscriberId = fdp.ConsumeIntegral<int64_t>();
    Template tplt;
    tplt.update_ = ConsumeSqlTextFromPool(fdp);
    tplt.scheduler_ = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    uint8_t count = fdp.ConsumeIntegral<uint8_t>() % MAX_PREDICATE_NODE_COUNT;
    for (uint8_t i = 0; i < count; i++) {
        std::string key = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
        tplt.predicates_.emplace_back(key, ConsumeSqlTextFromPool(fdp));
    }
    dataShareServiceImpl->AddTemplate(uri, subscriberId, tplt);
}

void DelTemplateFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    int64_t subscriberId = fdp.ConsumeIntegral<int64_t>();
    dataShareServiceImpl->DelTemplate(uri, subscriberId);
}

void NotifyObserverFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    dataShareServiceImpl->NotifyObserver(uri);
}

void GetDataFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string bundleNameOfProvider = fdp.ConsumeRandomLengthString(MAX_TEXT_LENGTH);
    int32_t errorCode = 0;
    dataShareServiceImpl->GetData(bundleNameOfProvider, errorCode);
}

void GetSilentProxyStatusFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    bool isCreateHelper = fdp.ConsumeBool();
    dataShareServiceImpl->GetSilentProxyStatus(uri, isCreateHelper);
}

void EnableSilentProxyFuzz(FuzzedDataProvider &fdp)
{
    std::shared_ptr<DataShareServiceImpl> dataShareServiceImpl = std::make_shared<DataShareServiceImpl>();
    std::string uri = ConsumeUriFromPool(fdp);
    bool enable = fdp.ConsumeBool();
    dataShareServiceImpl->EnableSilentProxy(uri, enable);
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
        case OHOS::FUZZ_INSERT_EX:
            OHOS::InsertExFuzz(fdp);
            break;
        case OHOS::FUZZ_QUERY:
            OHOS::QueryFuzz(fdp);
            break;
        case OHOS::FUZZ_UPDATE_EX:
            OHOS::UpdateExFuzz(fdp);
            break;
        case OHOS::FUZZ_DELETE_EX:
            OHOS::DeleteExFuzz(fdp);
            break;
        case OHOS::FUZZ_ADD_TEMPLATE:
            OHOS::AddTemplateFuzz(fdp);
            break;
        case OHOS::FUZZ_DEL_TEMPLATE:
            OHOS::DelTemplateFuzz(fdp);
            break;
        case OHOS::FUZZ_NOTIFY_OBSERVER:
            OHOS::NotifyObserverFuzz(fdp);
            break;
        case OHOS::FUZZ_GET_DATA:
            OHOS::GetDataFuzz(fdp);
            break;
        case OHOS::FUZZ_GET_SILENT_PROXY_STATUS:
            OHOS::GetSilentProxyStatusFuzz(fdp);
            break;
        default:
            OHOS::EnableSilentProxyFuzz(fdp);
            break;
    }
    return 0;
}
