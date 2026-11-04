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

#include "udmf_fuse_mount_adapter.h"

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>

#include "iservice_registry.h"
#include "log_print.h"
#include "storage_manager_proxy.h"
#include "system_ability_definition.h"

namespace OHOS::UDMF {
namespace {
int32_t PrepareMountPoint(const std::string &mountPoint)
{
    // Storage prepares the per-user parent directory. Its child must exist before storage validates realpath.
    constexpr mode_t MOUNT_POINT_MODE = S_IRWXU | S_IXGRP | S_IXOTH;
    if (mkdir(mountPoint.c_str(), MOUNT_POINT_MODE) == 0) {
        return 0;
    }
    int32_t error = errno;
    if (error != EEXIST) {
        return -error;
    }
    struct stat info {};
    if (lstat(mountPoint.c_str(), &info) != 0) {
        return -errno;
    }
    return S_ISDIR(info.st_mode) ? 0 : -ENOTDIR;
}

sptr<StorageManager::IStorageManager> GetStorageManagerProxy()
{
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgr == nullptr) {
        ZLOGE("Get system ability manager failed");
        return nullptr;
    }
    auto remoteObject = samgr->GetSystemAbility(STORAGE_MANAGER_MANAGER_ID);
    if (remoteObject == nullptr) {
        ZLOGE("Get storage manager system ability failed");
        return nullptr;
    }
    return iface_cast<StorageManager::IStorageManager>(remoteObject);
}
} // namespace

int32_t UdmfFuseMountAdapter::Mount(int32_t userId, const std::string &mountPoint, int &fuseFd)
{
    fuseFd = -1;
    int32_t ret = PrepareMountPoint(mountPoint);
    if (ret != 0) {
        ZLOGE("Prepare UDMF FUSE mount point failed, userId:%{public}d ret:%{public}d", userId, ret);
        return ret;
    }
    auto proxy = GetStorageManagerProxy();
    if (proxy == nullptr) {
        return -EIO;
    }
    ret = proxy->MountUdmfClipFuse(userId, mountPoint, fuseFd);
    if (ret != 0 || fuseFd < 0) {
        if (fuseFd >= 0) {
            (void)close(fuseFd);
            fuseFd = -1;
        }
        ZLOGE("Mount UDMF FUSE failed, userId:%{public}d ret:%{public}d", userId, ret);
        return ret == 0 ? -EBADF : ret;
    }
    return 0;
}

int32_t UdmfFuseMountAdapter::Unmount(int32_t userId, const std::string &mountPoint)
{
    auto proxy = GetStorageManagerProxy();
    if (proxy == nullptr) {
        return -EIO;
    }
    int32_t ret = proxy->UMountUdmfClipFuse(userId, mountPoint);
    if (ret != 0) {
        ZLOGE("Unmount UDMF FUSE failed, userId:%{public}d ret:%{public}d", userId, ret);
    }
    return ret;
}

} // namespace OHOS::UDMF
