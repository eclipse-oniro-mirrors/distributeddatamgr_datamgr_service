/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DATASHARESERVICE_RDB_DELEGATE_H
#define DATASHARESERVICE_RDB_DELEGATE_H

#include <mutex>
#include <string>

#include "concurrent_map.h"
#include "db_delegate.h"
#include "rdb_errno.h"
#include "rdb_helper.h"
#include "rdb_store.h"
#include "uri_utils.h"
#include "rdb_utils.h"

namespace OHOS::DataShare {
using namespace OHOS::NativeRdb;
class RdbDelegate final : public DBDelegate {
public:
    explicit RdbDelegate();
    ~RdbDelegate();
    bool Init(const DistributedData::StoreMetaData &meta, int version,
        bool registerFunction, const std::string &extUri, const std::string &backup) override;
    std::pair<int, std::shared_ptr<DataShareResultSet>> Query(const std::string &tableName,
        const DataSharePredicates &predicates, const std::vector<std::string> &columns,
        int32_t callingPid, uint32_t callingTokenId) override;
    std::string Query(const std::string &sql, const std::vector<std::string> &selectionArgs) override;
    std::shared_ptr<NativeRdb::ResultSet> QuerySql(const std::string &sql) override;
    std::pair<int, int64_t> UpdateSql(const std::string &sql) override;
    bool IsInvalid() override;
    std::pair<int64_t, int64_t> InsertEx(const std::string &tableName,
        const DataShareValuesBucket &valuesBucket) override;
    std::pair<int64_t, int64_t> UpdateEx(const std::string &tableName,
        const DataSharePredicates &predicate, const DataShareValuesBucket &valuesBucket) override;
    std::pair<int64_t, int64_t> DeleteEx(const std::string &tableName,
        const DataSharePredicates &predicate) override;
private:
    void TryAndSend(int errCode);
    std::pair<int, RdbStoreConfig> GetConfig(const DistributedData::StoreMetaData &meta, bool registerFunction);
    bool IsLimit(int count, int32_t callingPid, uint32_t callingTokenId);
    static std::atomic<int32_t> resultSetCount;
    static ConcurrentMap<uint32_t, int32_t> resultSetCallingPids;
    static constexpr std::chrono::milliseconds WAIT_TIME = std::chrono::milliseconds(50);
    std::shared_ptr<RdbStore> store_;
    int errCode_ = E_OK;
    static constexpr int RETRY = 3;
    static constexpr const char *DUAL_WRITE = "dualWrite";
    static constexpr const char *PERIODIC = "periodic";
    uint32_t tokenId_ = 0;
    std::string bundleName_ = "";
    std::string storeName_ = "";
    int32_t haMode_ = 0;
    std::string extUri_ = "";
    std::string backup_ = "";
    std::string user_ = "";
    std::mutex initMutex_;
    bool isInited_ = false;
};
class DefaultOpenCallback : public RdbOpenCallback {
public:
    int OnCreate(RdbStore &rdbStore) override
    {
        return E_OK;
    }
    int OnUpgrade(RdbStore &rdbStore, int oldVersion, int newVersion) override
    {
        return E_OK;
    }
};
} // namespace OHOS::DataShare
#endif // DATASHARESERVICE_RDB_DELEGATE_H
