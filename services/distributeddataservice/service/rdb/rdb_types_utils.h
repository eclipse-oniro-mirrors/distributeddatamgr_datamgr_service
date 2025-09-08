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

#ifndef OHOS_DISTRIBUTED_DATA_DATAMGR_SERVICE_RDB_RDB_TYPE_UTILS_H
#define OHOS_DISTRIBUTED_DATA_DATAMGR_SERVICE_RDB_RDB_TYPE_UTILS_H
#include <string>
#include <vector>

#include "rdb_types.h"
#include "store/general_value.h"
namespace OHOS::DistributedRdb {
class RdbTypesUtils final {
public:
    static std::vector<std::string> GetSearchableTables(const RdbChangedData &changedData);
    static std::vector<std::string> GetP2PTables(const RdbChangedData &changedData);
    static std::vector<DistributedData::Reference> Convert(const std::vector<Reference> &references);
};
} // namespace OHOS::DistributedRdb
#endif // OHOS_DISTRIBUTED_DATA_DATAMGR_SERVICE_RDB_RDB_TYPE_UTILS_H
