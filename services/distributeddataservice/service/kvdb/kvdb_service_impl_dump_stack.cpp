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

#define LOG_TAG "KvdbDumpStack"
#include <unistd.h>

#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "directory/directory_manager.h"
#include "ipc_skeleton.h"
#include "kv_hmfs_tag_util.h"
#include "kvdb_service_impl.h"
#include "log_print.h"
#include "tokenid_kit.h"
#include "utils/anonymous.h"

namespace OHOS {
namespace DistributedKv {
using namespace OHOS::DistributedData;
using namespace OHOS::Security::AccessToken;
namespace {
constexpr const char *KV_DB_SUB_DIR = "/single_ver/";
constexpr const char *KV_MAIN_DB = "main/gen_natural_store.db";
constexpr const char *KV_META_DB = "meta/meta.db";
constexpr const char *KV_WAL_SUFFIX = "-wal";
constexpr const char *KV_SHM_SUFFIX = "-shm";
constexpr const char *PATH_SEPARATOR = "/";
} // namespace

void KVDBServiceImpl::SetDumpStackTags(const StoreMetaData &metaData, const bool &isCustomDir)
{
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(IPCSkeleton::GetCallingTokenID());
    if (tokenType != TOKEN_NATIVE && !TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID())) {
        ZLOGW("dumpStackOnFileDeletion only for system app or SA, bundle:%{public}s", metaData.bundleName.c_str());
        return;
    }
    StoreMetaData meta = metaData;
    if (isCustomDir) {
        if (meta.customDir.empty() && AccessTokenKit::GetTokenTypeFlag(meta.tokenId) == TOKEN_HAP) {
            size_t pos = meta.dataDir.find_last_of(PATH_SEPARATOR);
            std::string customDir;
            if (pos != std::string::npos && pos < meta.dataDir.size() - 1) {
                customDir = meta.dataDir.substr(pos + 1);
            }
            meta.customDir = AssembleCustomDir(meta, customDir);
        }
        meta.dataDir = metaData.dataDir;
    } else if (meta.dataDir.empty()) {
        meta.dataDir = DirectoryManager::GetInstance().GetStorePath(meta);
    }
    std::string storeDir;
    auto dbStatus = DBManager::GetDatabaseDir(meta.storeId, storeDir);
    if (dbStatus != DBStatus::OK) {
        return;
    }
    std::string dir = meta.customDir.empty() ? meta.dataDir : meta.customDir;
    std::string base = dir + "/" + storeDir + KV_DB_SUB_DIR;
    const std::vector<std::string> files = { base + KV_MAIN_DB, base + KV_MAIN_DB + KV_WAL_SUFFIX,
        base + KV_MAIN_DB + KV_SHM_SUFFIX, base + KV_META_DB, base + KV_META_DB + KV_WAL_SUFFIX,
        base + KV_META_DB + KV_SHM_SUFFIX };
    for (const auto &file : files) {
        if (access(file.c_str(), F_OK) != 0) {
            continue;
        }
        if (KvHmfsTagUtil::GetKeyFileFlag(file) == KvHmfsTagUtil::FLAG_SET) {
            continue;
        }
        if (KvHmfsTagUtil::SetKeyFileFlag(file) != 0) {
            ZLOGW("set dump stack tag fail, store:%{public}s, path:%{public}s",
                Anonymous::Change(meta.storeId).c_str(), Anonymous::Change(file).c_str());
        }
    }
}
} // namespace DistributedKv
} // namespace OHOS
