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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_UTILS_BASE64_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_UTILS_BASE64_H

#include <string>
#include <vector>
#include "visibility.h"
namespace OHOS::DistributedData::Base64 {
API_EXPORT std::string Encode(const std::vector<uint8_t> &source);
API_EXPORT std::vector<uint8_t> Decode(const std::string &encoded);
} // namespace OHOS::DistributedData::Base64

#endif /* OHOS_DISTRIBUTED_DATA_SERVICES_FRAMEWORK_UTILS_BASE64_H */
