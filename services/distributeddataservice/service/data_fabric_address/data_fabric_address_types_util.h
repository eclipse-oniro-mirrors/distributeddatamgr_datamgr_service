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

#ifndef DATA_FABRIC_ADDRESS_TYPES_UTIL_H
#define DATA_FABRIC_ADDRESS_TYPES_UTIL_H

#include "data_fabric_address_types.h"
#include "itypes_util.h"

namespace OHOS::ITypesUtil {
using DataFabricAddressParams = NativePreferences::DataFabricAddressParams;

template<>
bool Marshalling(const DataFabricAddressParams &value, MessageParcel &parcel);

template<>
bool Unmarshalling(DataFabricAddressParams &value, MessageParcel &parcel);
}
#endif // DATA_FABRIC_ADDRESS_TYPES_UTIL_H
