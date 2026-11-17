/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_TYPES_UTIL_MOCK_H
#define OHOS_TYPES_UTIL_MOCK_H

#include <climits>
#include <map>
#include <memory>

#include "message_parcel.h"
#include "virtual_entry.h"
#include "visibility.h"

namespace OHOS {
namespace ITypesUtil {
    // Keep virtual-tree decoding real while other IPC paths use this test mock.
    template<typename T>
    bool Marshalling(const T &input, MessageParcel &parcel);
    template<typename T>
    bool Unmarshalling(T &output, MessageParcel &parcel);
    template<>
    bool API_EXPORT Marshalling(const UDMF::VirtualEntry &input, MessageParcel &parcel);
    template<>
    bool API_EXPORT Unmarshalling(UDMF::VirtualEntry &output, MessageParcel &parcel);
    template<typename T, typename... Types>
    static bool Marshal(MessageParcel &parcel, const T &first, const Types &...others);
    template<typename T, typename... Types>
    static bool Unmarshal(MessageParcel &parcel, T &first, Types &...others);
} // namespace ITypesUtil

template<typename T, typename... Types>
bool ITypesUtil::Marshal(MessageParcel &parcel, const T &first, const Types &...others)
{
    return false;
}

template<typename T, typename... Types>
bool ITypesUtil::Unmarshal(MessageParcel &parcel, T &first, Types &...others)
{
    return true;
}
}
#endif //OHOS_TYPES_UTIL_MOCK_H