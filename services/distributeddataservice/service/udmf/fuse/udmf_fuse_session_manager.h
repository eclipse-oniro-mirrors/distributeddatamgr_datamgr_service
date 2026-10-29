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

#ifndef UDMF_FUSE_SESSION_MANAGER_H
#define UDMF_FUSE_SESSION_MANAGER_H

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "executor_pool.h"
#include "iremote_object.h"
#include "virtual_entry.h"

namespace OHOS::UDMF {

class UdmfFuseController;

// This manager owns the mount lifetime. It deliberately has no application
// visible FUSE descriptor or backing-file path.
class UdmfFuseSessionManager final {
public:
    enum class State : uint8_t {
        PENDING_DROP,
        ACTIVE,
        DRAINING,
    };

    struct SessionInfo {
        int32_t userId = -1;
        uint32_t sourceTokenId = 0;
        uint32_t targetTokenId = 0;
        int32_t targetUid = -1;
        int32_t targetGid = -1;
        uint64_t generation = 0;
        uint32_t recordIndex = 0;
        VirtualEntry root;
        sptr<IRemoteObject> provider;
        sptr<IRemoteObject::DeathRecipient> deathRecipient;
        ExecutorPool::TaskId expiryTask = ExecutorPool::INVALID_TASK_ID;
        ExecutorPool::TaskId cleanupTask = ExecutorPool::INVALID_TASK_ID;
        std::string alias;
        State state = State::PENDING_DROP;
        uint32_t openCount = 0;
    };

    static UdmfFuseSessionManager &GetInstance();
    void SetExecutor(const std::shared_ptr<ExecutorPool> &executor);

    // Register is called while the drag is being prepared. It must not mount
    // FUSE; cancelled drags consequently allocate no kernel resources.
    int32_t Register(const std::string &sessionId, const SessionInfo &session);
    bool Get(const std::string &sessionId, SessionInfo &session) const;
    int32_t Activate(
        const std::string &sessionId, uint32_t targetTokenId, int32_t targetUid, int32_t targetGid, std::string &uri);
    int32_t AcquireOpen(const std::string &sessionId, int32_t callingUid);
    void ReleaseOpen(const std::string &sessionId);
    void Remove(const std::string &sessionId);

    static std::string GetMountPoint(int32_t userId);
    static std::string GetAppMountPoint(int32_t userId);
    static bool IsValid(const VirtualEntry &entry);

private:
    UdmfFuseSessionManager() = default;
    bool HasActiveSessionLocked(int32_t userId) const;
    void DecreasePendingSessionLocked(uint32_t sourceTokenId);
    void DecreaseActiveSessionLocked(int32_t userId, uint32_t sourceTokenId);
    void CancelCleanupTaskLocked(SessionInfo &session);
    void ScheduleCleanupTaskLocked(
        const std::string &sessionId, SessionInfo &session, const std::chrono::seconds &delay);
    void ScheduleActiveSessionLocked(const std::string &sessionId, SessionInfo &session);
    int32_t MountUserLocked(int32_t userId);
    int32_t AddControllerSessionLocked(const std::string &sessionId, SessionInfo &session, int32_t targetUid,
        int32_t targetGid, std::string &relativePath);
    void TryUnmountUser(int32_t userId);
    void TryUnmountUserLocked(int32_t userId);
    void Expire(const std::string &sessionId, uint64_t generation);
    void CleanupInactive(const std::string &sessionId, uint64_t generation);

    mutable std::mutex mutex_;
    std::map<std::string, SessionInfo> sessions_;
    uint32_t pendingSessionCount_ = 0;
    uint32_t activeSessionCount_ = 0;
    std::map<uint32_t, uint32_t> pendingSourceSessionCounts_;
    std::map<uint32_t, uint32_t> activeSourceSessionCounts_;
    std::map<int32_t, uint32_t> activeSessionCounts_;
    std::map<int32_t, std::shared_ptr<UdmfFuseController>> controllers_;
    std::shared_ptr<ExecutorPool> executor_;
};

} // namespace OHOS::UDMF

#endif // UDMF_FUSE_SESSION_MANAGER_H
