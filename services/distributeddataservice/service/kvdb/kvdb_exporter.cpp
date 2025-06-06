/*
* Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "KVDBExporter"
#include "kvdb_exporter.h"

#include "backup_manager.h"
#include "dfx/reporter.h"
#include "directory/directory_manager.h"
#include "kvdb_general_store.h"
#include "log_print.h"
#include "utils/anonymous.h"
namespace OHOS::DistributedKv {
using namespace OHOS::DistributedData;
using namespace OHOS::DistributedDataDfx;
__attribute__((used)) KVDBExporter KVDBExporter::instance_;

void KVDBExporter::Exporter(const StoreMetaData &meta, const std::string &backupPath, bool &result)
{
    DBManager manager(meta.appId, meta.user);
    auto path = DirectoryManager::GetInstance().GetStorePath(meta);
    manager.SetKvStoreConfig({ path });
    auto dbPassword = KVDBGeneralStore::GetDBPassword(meta);
    auto dbOption = KVDBGeneralStore::GetDBOption(meta, dbPassword);

    manager.GetKvStore(meta.storeId, dbOption, [&manager, &backupPath, &dbPassword, &result]
        (DistributedDB::DBStatus dbStatus, DistributedDB::KvStoreNbDelegate *delegate) {
        if (delegate == nullptr) {
            ZLOGE("Auto backup delegate is null");
            result = false;
            return;
        }
        dbStatus = delegate->CheckIntegrity();
        if (dbStatus != DistributedDB::DBStatus::OK) {
            ZLOGE("CheckIntegrity fail, dbStatus:%{public}d, backupPath:%{public}s", dbStatus,
                Anonymous::Change(backupPath).c_str());
            result = false;
            return;
        }
        dbStatus = delegate->Export(backupPath, dbPassword);
        result = (dbStatus == DistributedDB::DBStatus::OK) ? true : false;
        manager.CloseKvStore(delegate);
    });
    std::string message;
    message.append(" backup name [")
        .append(backupPath)
        .append("], isEncrypt [")
        .append(std::to_string(meta.isEncrypt))
        .append("]")
        .append("], backup result  [")
        .append(std::to_string(result))
        .append("]");
    Reporter::GetInstance()->GetBehaviourReporter()->Report(
        { meta.account, meta.appId, meta.storeId, BehaviourType::DATABASE_BACKUP, message });
}

KVDBExporter::KVDBExporter() noexcept
{
    BackupManager::GetInstance().RegisterExporter(KvStoreType::SINGLE_VERSION, Exporter);
    BackupManager::GetInstance().RegisterExporter(KvStoreType::DEVICE_COLLABORATION, Exporter);
}
} // namespace OHOS::DistributedKv
