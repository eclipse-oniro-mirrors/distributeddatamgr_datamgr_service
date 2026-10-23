/**
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

#include "autocacheobserver_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "store/auto_cache.h"
#include "store/watcher_bridge.h"

namespace OHOS::DistributedData {
namespace {
constexpr int32_t FUZZ_STORE_TYPE = 29; // Reserved fake type; never overwrite a production creator.
constexpr int32_t CREATOR_END = 30;
constexpr uint8_t MAX_ROUNDS = 8;
constexpr size_t MAX_STORE_ID_LENGTH = 32;

void Verify(FuzzedDataProvider &fdp)
{
    AutoCache &cache = AutoCache::GetInstance();
    uint8_t rounds = fdp.ConsumeIntegralInRange<uint8_t>(1, MAX_ROUNDS);
    for (uint8_t round = 0; round < rounds; ++round) {
        int32_t type = fdp.ConsumeBool() ? FUZZ_STORE_TYPE : fdp.ConsumeIntegral<int32_t>();
        if (type >= 0 && type < CREATOR_END) {
            type = FUZZ_STORE_TYPE;
        }
        int32_t status = fdp.ConsumeIntegral<int32_t>();
        bool emptyGetter = fdp.ConsumeBool();
        AutoCache::Creator creator = [status](const StoreMetaData &, const AutoCache::StoreOption &) {
            return std::pair<int32_t, GeneralStore *>{ status, nullptr };
        };
        AutoCache::WatcherFactory factory = [emptyGetter](const StoreMetaData &) -> WatcherBridge::Getter {
            return emptyGetter ? WatcherBridge::Getter{} : []() { return AutoCache::Watchers{}; };
        };
        if (fdp.ConsumeBool()) {
            creator = nullptr;
        }
        if (fdp.ConsumeBool()) {
            factory = nullptr;
        }
        cache.RegCreator(type, creator);
        cache.RegWatcherFactory(type, fdp.ConsumeBool() ? factory : nullptr);
        StoreMetaData meta;
        meta.storeType = type;
        meta.tokenId = fdp.ConsumeIntegral<uint32_t>();
        meta.user = "0"; // Avoid account services; this target never creates a real delegate.
        meta.area = GeneralStore::EL1;
        meta.storeId = fdp.ConsumeRandomLengthString(MAX_STORE_ID_LENGTH);
        cache.GetDBStore(meta);
    }
    cache.RegCreator(FUZZ_STORE_TYPE, nullptr);
    cache.RegWatcherFactory(FUZZ_STORE_TYPE, nullptr);
}
} // namespace
} // namespace OHOS::DistributedData

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (data == nullptr || size == 0) {
        return 0;
    }
    FuzzedDataProvider fdp(data, size);
    OHOS::DistributedData::Verify(fdp);
    return 0;
}
