/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTEDDATAMGR_VERSION_META_DATA_H
#define DISTRIBUTEDDATAMGR_VERSION_META_DATA_H
#include "serializable/serializable.h"

namespace OHOS::DistributedData {
class API_EXPORT VersionMetaData final : public Serializable {
public:
    static constexpr int32_t CURRENT_VERSION = 5;
    static constexpr int32_t UPDATE_STORE_META_KEY_VERSION = 5;
    static constexpr int32_t UPDATE_SYNC_META_VERSION = 4;
    static constexpr int32_t INVALID_VERSION = -1;
    int32_t version = INVALID_VERSION;

    API_EXPORT VersionMetaData();
    API_EXPORT ~VersionMetaData();
    API_EXPORT bool Marshal(json &node) const override;
    API_EXPORT bool Unmarshal(const json &node) override;
    API_EXPORT std::string GetKey() const;

private:
    static constexpr const char *KEY_PREFIX = "VersionKey";
};
} // namespace OHOS::DistributedData
#endif // DISTRIBUTEDDATAMGR_VERSION_META_DATA_H