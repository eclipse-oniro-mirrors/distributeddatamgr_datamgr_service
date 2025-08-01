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
#define LOG_TAG "RdbAdaptor"
#include "rdb_delegate.h"

#include "crypto/crypto_manager.h"
#include "datashare_errno.h"
#include "datashare_radar_reporter.h"
#include "device_manager_adapter.h"
#include "extension_connect_adaptor.h"
#include "int_wrapper.h"
#include "metadata/meta_data_manager.h"
#include "metadata/store_meta_data.h"
#include "metadata/secret_key_meta_data.h"
#include "resultset_json_formatter.h"
#include "log_print.h"
#include "rdb_errno.h"
#include "rdb_utils.h"
#include "scheduler_manager.h"
#include "string_wrapper.h"
#include "utils/anonymous.h"
#include "want_params.h"
#include "db_delegate.h"
#include "log_debug.h"
#include "ipc_skeleton.h"
#include "common_utils.h"

namespace OHOS::DataShare {
constexpr static int32_t MAX_RESULTSET_COUNT = 32;
constexpr static int64_t TIMEOUT_TIME = 500;
std::atomic<int32_t> RdbDelegate::resultSetCount = 0;
ConcurrentMap<uint32_t, int32_t> RdbDelegate::resultSetCallingPids;
enum REMIND_TIMER_ARGS : int32_t {
    ARG_DB_PATH = 0,
    ARG_TOKEN_ID,
    ARG_URI,
    ARG_SUBSCRIBER_ID,
    ARG_BUNDLE_NAME,
    ARG_USER_ID,
    ARG_STORE_ID,
    ARG_HA_MODE,
    ARG_TIME,
    ARGS_SIZE
};
std::string RemindTimerFunc(const std::vector<std::string> &args)
{
    size_t size = args.size();
    if (size != ARGS_SIZE) {
        ZLOGE("RemindTimerFunc args size error, %{public}zu", size);
        return "";
    }
    DistributedData::StoreMetaData metaData;
    metaData.tokenId = static_cast<uint32_t>(std::atol(args[ARG_TOKEN_ID].c_str()));
    metaData.storeId = args[ARG_STORE_ID];
    metaData.dataDir = args[ARG_DB_PATH];
    metaData.haMode = std::atol(args[ARG_HA_MODE].c_str());
    Key key(args[ARG_URI], std::atoll(args[ARG_SUBSCRIBER_ID].c_str()), args[ARG_BUNDLE_NAME]);
    int64_t reminderTime = std::atoll(args[ARG_TIME].c_str());
    int32_t userId = std::atol(args[ARG_USER_ID].c_str());
    SchedulerManager::GetInstance().SetTimer(userId, metaData, key, reminderTime);
    return args[ARG_TIME];
}

std::pair<int, RdbStoreConfig> RdbDelegate::GetConfig(const DistributedData::StoreMetaData &meta,
    bool registerFunction)
{
    RdbStoreConfig config(meta.dataDir);
    config.SetCreateNecessary(false);
    config.SetHaMode(meta.haMode);
    config.SetBundleName(meta.bundleName);
    if (meta.isEncrypt) {
        DistributedData::SecretKeyMetaData secretKeyMeta;
        auto metaKey = meta.GetSecretKey();
        if (!DistributedData::MetaDataManager::GetInstance().LoadMeta(metaKey, secretKeyMeta, true) ||
            secretKeyMeta.sKey.empty()) {
            return std::make_pair(E_DB_NOT_EXIST, config);
        }
        DistributedData::CryptoManager::CryptoParams decryptParams = { .area = secretKeyMeta.area,
            .userId = meta.user, .nonce = secretKeyMeta.nonce };
        auto decryptKey = DistributedData::CryptoManager::GetInstance().Decrypt(secretKeyMeta.sKey, decryptParams);
        if (decryptKey.empty()) {
            return std::make_pair(E_ERROR, config);
        }
        // update secret key of area or nonce
        DistributedData::CryptoManager::GetInstance().UpdateSecretMeta(decryptKey, meta, metaKey, secretKeyMeta);
        config.SetEncryptKey(decryptKey);
        std::fill(decryptKey.begin(), decryptKey.end(), 0);
    }
    if (registerFunction) {
        config.SetScalarFunction("remindTimer", ARGS_SIZE, RemindTimerFunc);
    }
    return std::make_pair(E_OK, config);
}

RdbDelegate::RdbDelegate()
{
}

bool RdbDelegate::Init(const DistributedData::StoreMetaData &meta, int version,
    bool registerFunction, const std::string &extUri, const std::string &backup)
{
    if (isInited_) {
        return true;
    }
    std::lock_guard<std::mutex> lock(initMutex_);
    if (isInited_) {
        return true;
    }
    tokenId_ = meta.tokenId;
    bundleName_ = meta.bundleName;
    storeName_ = meta.storeId;
    haMode_ = meta.haMode;
    extUri_ = extUri;
    backup_ = backup;
    user_ = meta.user;
    auto [err, config] = GetConfig(meta, registerFunction);
    if (err != E_OK) {
        ZLOGW("Get rdbConfig failed, errCode is %{public}d, dir is %{public}s", err,
            URIUtils::Anonymous(meta.dataDir).c_str());
        return false;
    }
    DefaultOpenCallback callback;
    TimeoutReport timeoutReport({meta.bundleName, "", meta.storeId, __FUNCTION__, 0});
    store_ = RdbHelper::GetRdbStore(config, version, callback, errCode_);
    auto callingPid = IPCSkeleton::GetCallingPid();
    timeoutReport.Report(meta.user, callingPid, -1, meta.instanceId);
    if (errCode_ != E_OK) {
        ZLOGW("GetRdbStore failed, errCode is %{public}d, dir is %{public}s", errCode_,
            URIUtils::Anonymous(meta.dataDir).c_str());
        RdbDelegate::TryAndSend(errCode_);
        return false;
    }
    isInited_ = true;
    return true;
}

RdbDelegate::~RdbDelegate()
{
    ZLOGI("Destruct. BundleName: %{public}s. StoreName: %{public}s. user: %{public}s", bundleName_.c_str(),
        DistributedData::Anonymous::Change(storeName_).c_str(), user_.c_str());
}
void RdbDelegate::TryAndSend(int errCode)
{
    if (errCode != E_SQLITE_CORRUPT || (haMode_ == HAMode::SINGLE && (backup_ != DUAL_WRITE && backup_ != PERIODIC))) {
        return;
    }
    ZLOGE("Database corruption. BundleName: %{public}s. StoreName: %{public}s. ExtUri: %{public}s",
        bundleName_.c_str(), storeName_.c_str(), URIUtils::Anonymous(extUri_).c_str());
    AAFwk::WantParams params;
    params.SetParam("BundleName", AAFwk::String::Box(bundleName_));
    params.SetParam("StoreName", AAFwk::String::Box(storeName_));
    params.SetParam("StoreStatus", AAFwk::Integer::Box(1));
    ExtensionConnectAdaptor::TryAndWait(extUri_, bundleName_, params);
}

std::pair<int64_t, int64_t> RdbDelegate::InsertEx(const std::string &tableName,
    const DataShareValuesBucket &valuesBucket)
{
    if (store_ == nullptr) {
        ZLOGE("store is null");
        return std::make_pair(E_DB_ERROR, 0);
    }
    int64_t rowId = 0;
    ValuesBucket bucket = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBucket);
    int ret = store_->Insert(rowId, tableName, bucket);
    if (ret != E_OK) {
        ZLOGE("Insert failed %{public}s %{public}d", tableName.c_str(), ret);
        RADAR_REPORT(__FUNCTION__, RadarReporter::SILENT_ACCESS, RadarReporter::PROXY_CALL_RDB,
            RadarReporter::FAILED, RadarReporter::ERROR_CODE, RadarReporter::INSERT_RDB_ERROR);
        if (ret == E_SQLITE_ERROR) {
            EraseStoreCache(tokenId_);
        }
        RdbDelegate::TryAndSend(ret);
        return std::make_pair(E_DB_ERROR, rowId);
    }
    return std::make_pair(E_OK, rowId);
}

std::pair<int64_t, int64_t> RdbDelegate::UpdateEx(
    const std::string &tableName, const DataSharePredicates &predicate, const DataShareValuesBucket &valuesBucket)
{
    if (store_ == nullptr) {
        ZLOGE("store is null");
        return std::make_pair(E_DB_ERROR, 0);
    }
    int changeCount = 0;
    ValuesBucket bucket = RdbDataShareAdapter::RdbUtils::ToValuesBucket(valuesBucket);
    RdbPredicates predicates = RdbDataShareAdapter::RdbUtils::ToPredicates(predicate, tableName);
    int ret = store_->Update(changeCount, bucket, predicates);
    if (ret != E_OK) {
        ZLOGE("Update failed  %{public}s %{public}d", tableName.c_str(), ret);
        RADAR_REPORT(__FUNCTION__, RadarReporter::SILENT_ACCESS, RadarReporter::PROXY_CALL_RDB,
            RadarReporter::FAILED, RadarReporter::ERROR_CODE, RadarReporter::UPDATE_RDB_ERROR);
        if (ret == E_SQLITE_ERROR) {
            EraseStoreCache(tokenId_);
        }
        RdbDelegate::TryAndSend(ret);
        return std::make_pair(E_DB_ERROR, changeCount);
    }
    return std::make_pair(E_OK, changeCount);
}

std::pair<int64_t, int64_t> RdbDelegate::DeleteEx(const std::string &tableName, const DataSharePredicates &predicate)
{
    if (store_ == nullptr) {
        ZLOGE("store is null");
        return std::make_pair(E_DB_ERROR, 0);
    }
    int changeCount = 0;
    RdbPredicates predicates = RdbDataShareAdapter::RdbUtils::ToPredicates(predicate, tableName);
    int ret = store_->Delete(changeCount, predicates);
    if (ret != E_OK) {
        ZLOGE("Delete failed  %{public}s %{public}d", tableName.c_str(), ret);
        RADAR_REPORT(__FUNCTION__, RadarReporter::SILENT_ACCESS, RadarReporter::PROXY_CALL_RDB,
            RadarReporter::FAILED, RadarReporter::ERROR_CODE, RadarReporter::DELETE_RDB_ERROR);
        if (ret == E_SQLITE_ERROR) {
            EraseStoreCache(tokenId_);
        }
        RdbDelegate::TryAndSend(ret);
        return std::make_pair(E_DB_ERROR, changeCount);
    }
    return std::make_pair(E_OK, changeCount);
}

std::pair<int, std::shared_ptr<DataShareResultSet>> RdbDelegate::Query(const std::string &tableName,
    const DataSharePredicates &predicates, const std::vector<std::string> &columns,
    int32_t callingPid, uint32_t callingTokenId)
{
    if (store_ == nullptr) {
        ZLOGE("store is null");
        return std::make_pair(errCode_, nullptr);
    }
    int count = resultSetCount.fetch_add(1);
    if (count >= MAX_RESULTSET_COUNT && IsLimit(count, callingPid, callingTokenId)) {
        resultSetCount--;
        return std::make_pair(E_RESULTSET_BUSY, nullptr);
    }
    RdbPredicates rdbPredicates = RdbDataShareAdapter::RdbUtils::ToPredicates(predicates, tableName);
    std::shared_ptr<NativeRdb::ResultSet> resultSet = store_->QueryByStep(rdbPredicates, columns);
    if (resultSet == nullptr) {
        RADAR_REPORT(__FUNCTION__, RadarReporter::SILENT_ACCESS, RadarReporter::PROXY_CALL_RDB,
            RadarReporter::FAILED, RadarReporter::ERROR_CODE, RadarReporter::QUERY_RDB_ERROR);
        ZLOGE("Query failed %{public}s, pid: %{public}d", tableName.c_str(), callingPid);
        resultSetCount--;
        return std::make_pair(E_ERROR, nullptr);
    }
    int err = resultSet->GetRowCount(count);
    RdbDelegate::TryAndSend(err);
    if (err == E_SQLITE_ERROR) {
        ZLOGE("query failed, err:%{public}d, pid:%{public}d", E_SQLITE_ERROR, callingPid);
        EraseStoreCache(tokenId_);
    }
    resultSetCallingPids.Compute(callingPid, [](const uint32_t &, int32_t &value) {
        ++value;
        return true;
    });
    int64_t beginTime = GetSystemTime();
    auto bridge = RdbDataShareAdapter::RdbUtils::ToResultSetBridge(resultSet);
    auto resultSetPtr = new (std::nothrow) DataShareResultSet(bridge);
    if (resultSetPtr == nullptr) {
        return std::make_pair(E_ERROR, nullptr);
    }
    auto result = std::shared_ptr<DataShareResultSet>(resultSetPtr, [callingPid, beginTime](auto p) {
        resultSetCount--;
        int64_t endTime = GetSystemTime();
        if (endTime - beginTime > TIMEOUT_TIME) {
            ZLOGE("pid %{public}d query time is %{public}" PRId64 ", %{public}d resultSet is used.", callingPid,
                (endTime - beginTime), resultSetCount.load());
        }
        resultSetCallingPids.ComputeIfPresent(callingPid, [](const uint32_t &, int32_t &value) {
            --value;
            return value > 0;
        });
        delete p;
    });
    return std::make_pair(E_OK, result);
}

std::string RdbDelegate::Query(const std::string &sql, const std::vector<std::string> &selectionArgs)
{
    if (store_ == nullptr) {
        ZLOGE("store is null");
        return "";
    }
    auto resultSet = store_->QueryByStep(sql, selectionArgs);
    if (resultSet == nullptr) {
        ZLOGE("Query failed %{private}s", sql.c_str());
        return "";
    }
    int rowCount;
    if (resultSet->GetRowCount(rowCount) == E_SQLITE_ERROR) {
        ZLOGE("query failed, err:%{public}d", E_SQLITE_ERROR);
        EraseStoreCache(tokenId_);
    }
    ResultSetJsonFormatter formatter(std::move(resultSet));
    return DistributedData::Serializable::Marshall(formatter);
}

std::shared_ptr<NativeRdb::ResultSet> RdbDelegate::QuerySql(const std::string &sql)
{
    if (store_ == nullptr) {
        ZLOGE("store is null");
        return nullptr;
    }
    auto resultSet = store_->QuerySql(sql);
    if (resultSet == nullptr) {
        ZLOGE("Query failed %{private}s", sql.c_str());
        return resultSet;
    }
    int rowCount;
    if (resultSet->GetRowCount(rowCount) == E_SQLITE_ERROR) {
        ZLOGE("query failed, err:%{public}d", E_SQLITE_ERROR);
        EraseStoreCache(tokenId_);
    }
    return resultSet;
}

std::pair<int, int64_t> RdbDelegate::UpdateSql(const std::string &sql)
{
    if (store_ == nullptr) {
        ZLOGE("store is null");
        return std::make_pair(E_ERROR, 0);
    }
    auto[ret, outValue] = store_->Execute(sql);
    if (ret != E_OK) {
        ZLOGE("execute update sql failed, err:%{public}d", ret);
        return std::make_pair(ret, 0);
    }
    int64_t rowCount = 0;
    outValue.GetLong(rowCount);
    return std::make_pair(ret, rowCount);
}

bool RdbDelegate::IsInvalid()
{
    return store_ == nullptr;
}

bool RdbDelegate::IsLimit(int count, int32_t callingPid, uint32_t callingTokenId)
{
    bool isFull = true;
    for (int32_t retryCount = 0; retryCount < RETRY; retryCount++) {
        std::this_thread::sleep_for(WAIT_TIME);
        if (resultSetCount.load() <= MAX_RESULTSET_COUNT) {
            isFull = false;
            break;
        }
    }
    if (!isFull) {
        return false;
    }
    std::string logStr;
    resultSetCallingPids.ForEach([&logStr](const uint32_t &key, const int32_t &value) {
        logStr += std::to_string(key) + ":" + std::to_string(value) + ";";
        return false;
    });
    ZLOGE("resultSetCount is full, pid: %{public}d, owner is %{public}s", callingPid, logStr.c_str());
    std::string appendix = "callingName:" + HiViewFaultAdapter::GetCallingName(callingTokenId).first;
    DataShareFaultInfo faultInfo{HiViewFaultAdapter::resultsetFull, "callingTokenId:" + std::to_string(callingTokenId),
        "Pid:" + std::to_string(callingPid), "owner:" + logStr, __FUNCTION__, E_RESULTSET_BUSY, appendix};
    HiViewFaultAdapter::ReportDataFault(faultInfo);
    return true;
}
} // namespace OHOS::DataShare