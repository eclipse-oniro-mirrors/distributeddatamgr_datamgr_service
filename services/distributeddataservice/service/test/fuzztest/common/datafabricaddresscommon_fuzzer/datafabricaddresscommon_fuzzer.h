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

#ifndef DATA_FABRIC_ADDRESS_COMMON_FUZZ_H
#define DATA_FABRIC_ADDRESS_COMMON_FUZZ_H

#include <cstddef>
#include <cstdint>

#include "data_fabric_address_service_stub.h"

namespace OHOS {
namespace DataFabricAddress {
class DataFabricAddressStubFuzz : public DataFabricAddressServiceStub {
public:
    int32_t Subscribe(const DataFabricAddressParams& inputParams,
        sptr<IDataFabricAddressCallback> callback) override;
    int32_t Unsubscribe(const DataFabricAddressParams& inputParams) override;
};

void DataFabricAddressCommonTestFuzzer(const uint8_t* data, size_t size, uint32_t code);
} // End of namespace DataFabricAddress
} // End of namespace OHOS
#endif // DATA_FABRIC_ADDRESS_COMMON_FUZZ_H