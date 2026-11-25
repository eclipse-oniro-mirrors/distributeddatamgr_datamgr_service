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
#include "kvdb_service_impl.h"

#include <unistd.h>

#include <string>
#include <vector>

#include "accesstoken_kit.h"
#include "ipc_skeleton.h"
#include "kv_hmfs_tag_util.h"
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

std::string GetDbRoot(const StoreMetaData &metaData, const Options &options)
{
    if (!options.isCustomDir) {
        return metaData.dataDir;
    }
    return metaData.customDir.empty() ? options.baseDir + "/kvdb" : metaData.customDir;
}
} // namespace

void KVDBServiceImpl::SetDumpStackTags(const StoreMetaData &metaData, const Options &options)
{
    if (AccessTokenKit::GetTokenTypeFlag(IPCSkeleton::GetCallingTokenID()) != TOKEN_NATIVE &&
        !TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID())) {
        ZLOGW("dumpStackOnFileDeletion only for system app or SA, bundle:%{public}s", metaData.bundleName.c_str());
        return;
    }
    std::string storeDir;
    if (DBManager::GetDatabaseDir(metaData.storeId, storeDir) != DBStatus::OK) {
        return;
    }
    StoreMetaData dumpMetaData = metaData;
    if (options.isCustomDir && dumpMetaData.customDir.empty() &&
        AccessTokenKit::GetTokenTypeFlag(dumpMetaData.tokenId) == TOKEN_HAP) {
        size_t pos = options.baseDir.find_last_of('/');
        std::string customDir;
        if (pos != std::string::npos && pos < options.baseDir.size() - 1) {
            customDir = options.baseDir.substr(pos + 1);
        }
        dumpMetaData.customDir = AssembleCustomDir(dumpMetaData, customDir);
    }
    std::string base = GetDbRoot(dumpMetaData, options) + "/" + storeDir + KV_DB_SUB_DIR;
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
                Anonymous::Change(metaData.storeId).c_str(), Anonymous::Change(file).c_str());
        }
    }
}
} // namespace DistributedKv
} // namespace OHOS
