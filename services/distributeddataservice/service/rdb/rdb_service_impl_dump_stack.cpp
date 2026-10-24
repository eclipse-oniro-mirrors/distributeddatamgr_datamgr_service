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

#define LOG_TAG "RdbDumpStack"
#include "rdb_service_impl.h"

#include "accesstoken_kit.h"
#include "hmfs_tag_util.h"
#include "ipc_skeleton.h"
#include "log_print.h"
#include "metadata/store_meta_data.h"
#include "tokenid_kit.h"
#include "unistd.h"
#include "utils/anonymous.h"

namespace OHOS {
namespace DistributedRdb {
using namespace OHOS::DistributedData;
using namespace OHOS::Security::AccessToken;

void RdbServiceImpl::SetDumpStackTags(const StoreMetaData &meta)
{
    // BR-7: only system apps and SAs may enable dump-stack tagging; silently skip
    // for other callers (the systemapi field is compile-time hidden from third-party
    // apps, and native callers are trusted SAs).
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto tokenType = AccessTokenKit::GetTokenTypeFlag(tokenId);
    if (tokenType != Security::AccessToken::TOKEN_NATIVE &&
        !TokenIdKit::IsSystemAppByFullTokenID(IPCSkeleton::GetCallingFullTokenID())) {
        ZLOGW("dumpStackOnFileDel is only for system apps and SAs, bundleName:%{public}s",
            meta.bundleName.c_str());
        return;
    }
    // BR-1/BR-3: tag only db/wal/shm on both the primary path and the replica path;
    // journal/binlog/dwr are out of scope.
    std::vector<std::string> tagPaths = { meta.dataDir, meta.dataDir + "-wal", meta.dataDir + "-shm" };
    std::string replicaDir = meta.replicaPath;
    while (replicaDir.length() > 1 && replicaDir.back() == '/') {
        replicaDir.pop_back();
    }
    // Mirrors SqliteUtils::GetSlavePath in relational_store (not exported for cross-
    // component use): <name-without-.db> + "-slave". A custom replicaPath is a directory
    // holding <store>-slave, while the default replica sits beside the primary db as
    // <dbPath>-slave. Both the custom-replica and default-replica layouts must be covered.
    std::string slavePath = replicaDir.empty() ? RemoveSuffix(meta.dataDir) + "-slave"
                                               : replicaDir + "/" + meta.storeId + "-slave";
    // The replica db is created lazily (first backup); tag it only when it exists so
    // single-mode stores never produce failed-ioctl noise.
    if (access(slavePath.c_str(), F_OK) == 0) {
        tagPaths.push_back(slavePath);
        tagPaths.push_back(slavePath + "-wal");
        tagPaths.push_back(slavePath + "-shm");
    }
    for (const auto &path : tagPaths) {
        if (path.empty()) {
            continue;
        }
        // BR-6/EX-5: query first, set only when the tag is absent (idempotent).
        if (HmfsTagUtil::GetKeyFileFlag(path) == HmfsTagUtil::FLAG_SET) {
            continue;
        }
        // BR-5/EX-1: silent degrade on failure; the tag is healed at the next
        // AfterOpen/Enable window.
        if (HmfsTagUtil::SetKeyFileFlag(path) != 0) {
            ZLOGW("set dump stack tag fail, bundleName:%{public}s, store:%{public}s, path:%{public}s",
                meta.bundleName.c_str(), meta.GetStoreAlias().c_str(), Anonymous::Change(path).c_str());
        }
    }
}
} // namespace DistributedRdb
} // namespace OHOS
