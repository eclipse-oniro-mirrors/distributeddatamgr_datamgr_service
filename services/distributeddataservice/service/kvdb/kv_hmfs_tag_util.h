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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICE_KVDB_KV_HMFS_TAG_UTIL_H
#define OHOS_DISTRIBUTED_DATA_SERVICE_KVDB_KV_HMFS_TAG_UTIL_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace DistributedKv {
class KvHmfsTagUtil {
public:
    static constexpr int FLAG_SET = 1; /* NOLINT */

    static int SetKeyFileFlag(const std::string &path);

    static int GetKeyFileFlag(const std::string &path);

private:
    static constexpr int FLAG_UNSET = 0;          /* NOLINT */
    static constexpr int MAX_FILE_NAME_LEN = 255; /* NOLINT */

    static bool IsValidFileName(const std::string &fileName);

    static int SetKeyFileFlag(int dirFd, const std::string &fileName);

    static int GetKeyFileFlag(int dirFd, const std::string &fileName);

    static int ExecuteIoctl(int dirFd, unsigned long cmd, const std::string &fileName, uint32_t *outFlags);

    static int ExecuteByPath(unsigned long cmd, const std::string &path, uint32_t *outFlags);

    static int NegateErrno(int err);
};
} // namespace DistributedKv
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DATA_SERVICE_KVDB_KV_HMFS_TAG_UTIL_H
