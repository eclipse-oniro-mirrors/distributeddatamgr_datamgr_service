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

#include "udmf_fuse_session_manager.h"

#include <cerrno>
#include <new>
#include <unordered_set>
#include <utility>

#include "log_print.h"
#include "udmf_fuse_controller.h"
#include "udmf_fuse_mount_adapter.h"
#include "utils/crypto.h"

namespace OHOS::UDMF {
namespace {
// /mnt/data is a shared mount tree. Appspawn exposes the per-user UDMF FUSE directory through a
// stable application-side path, so the mount is visible to the drop target without exposing user IDs.
constexpr char UDMF_FUSE_MOUNT_PREFIX[] = "/mnt/data/";
constexpr char UDMF_FUSE_MOUNT_SUFFIX[] = "/udmf_fuse";
constexpr char UDMF_FUSE_APP_MOUNT_POINT[] = "/data/storage/el2/udmf";
constexpr std::chrono::hours ACTIVE_SESSION_LEASE(24);
constexpr std::chrono::seconds INITIAL_OPEN_TIMEOUT(30);
constexpr std::chrono::seconds IDLE_SESSION_TIMEOUT(5);
constexpr size_t MAX_ENTRY_ID_BYTES = 1024;
constexpr size_t MAX_NAME_BYTES = 255;
constexpr uint32_t MAX_ENTRY_DEPTH = 64;
constexpr uint32_t MAX_ENTRY_COUNT = 4096;
constexpr uint32_t MAX_PENDING_SESSIONS = 8;
constexpr uint32_t MAX_PENDING_SESSIONS_PER_SOURCE = 4;
constexpr uint32_t MAX_ACTIVE_SESSIONS = 3;
constexpr uint32_t MAX_ACTIVE_SESSIONS_PER_SOURCE = 2;
constexpr int32_t ALIAS_LENGTH = 32;
constexpr int32_t ALIAS_MINIMUM = 'a';
constexpr int32_t ALIAS_MAXIMUM = 'z';

std::string GenerateAlias()
{
    auto random = DistributedData::Crypto::Random(ALIAS_LENGTH, ALIAS_MINIMUM, ALIAS_MAXIMUM);
    return random.size() == static_cast<size_t>(ALIAS_LENGTH) ? std::string(random.begin(), random.end()) : "";
}

bool IsValidEntry(const VirtualEntry &entry, uint32_t depth, uint32_t &count)
{
    if (depth > MAX_ENTRY_DEPTH || count >= MAX_ENTRY_COUNT) {
        return false;
    }
    ++count;
    if (entry.name.empty() || entry.name.size() > MAX_NAME_BYTES || entry.name == "." || entry.name == ".." ||
        entry.name.find_first_of("/\\") != std::string::npos || entry.name.find('\0') != std::string::npos) {
        return false;
    }
    if (entry.type == VirtualEntryType::FILE) {
        return !entry.id.empty() && entry.id.size() <= MAX_ENTRY_ID_BYTES && entry.size >= -1 && entry.subItems.empty();
    }
    if (entry.type != VirtualEntryType::DIRECTORY || entry.size != -1 || !entry.id.empty()) {
        return false;
    }
    std::unordered_set<std::string> names;
    for (const auto &child : entry.subItems) {
        if (!names.emplace(child.name).second || !IsValidEntry(child, depth + 1, count)) {
            return false;
        }
    }
    return true;
}

class ProviderDeathRecipient final : public IRemoteObject::DeathRecipient {
public:
    explicit ProviderDeathRecipient(std::string sessionId) : sessionId_(std::move(sessionId))
    {
    }

    void OnRemoteDied(const wptr<IRemoteObject> &remote) override
    {
        (void)remote;
        UdmfFuseSessionManager::GetInstance().Remove(sessionId_);
    }

private:
    std::string sessionId_;
};
} // namespace

UdmfFuseSessionManager &UdmfFuseSessionManager::GetInstance()
{
    static UdmfFuseSessionManager manager;
    return manager;
}

void UdmfFuseSessionManager::SetExecutor(const std::shared_ptr<ExecutorPool> &executor)
{
    std::lock_guard<std::mutex> lock(mutex_);
    executor_ = executor;
}

int32_t UdmfFuseSessionManager::Register(const std::string &sessionId, const SessionInfo &session)
{
    if (sessionId.empty() || session.userId < 0 || session.sourceTokenId == 0 || session.generation == 0 ||
        session.provider == nullptr || !IsValid(session.root)) {
        return -EINVAL;
    }
    SessionInfo stored = session;
    stored.deathRecipient = new (std::nothrow) ProviderDeathRecipient(sessionId);
    if (stored.deathRecipient == nullptr) {
        return -ENOMEM;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sessions_.find(sessionId) != sessions_.end()) {
            return -EEXIST;
        }
        auto sourceCount = pendingSourceSessionCounts_.find(session.sourceTokenId);
        if (pendingSessionCount_ >= MAX_PENDING_SESSIONS ||
            (sourceCount != pendingSourceSessionCounts_.end() &&
                sourceCount->second >= MAX_PENDING_SESSIONS_PER_SOURCE)) {
            ZLOGW("Reject virtual entry registration because pending quota is exhausted, pending:%{public}u",
                pendingSessionCount_);
            return -EAGAIN;
        }
        sessions_.emplace(sessionId, stored);
        ++pendingSessionCount_;
        ++pendingSourceSessionCounts_[session.sourceTokenId];
    }
    if (!session.provider->AddDeathRecipient(stored.deathRecipient) || session.provider->IsObjectDead()) {
        Remove(sessionId);
        return -EPIPE;
    }
    return 0;
}

bool UdmfFuseSessionManager::Get(const std::string &sessionId, SessionInfo &session) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return false;
    }
    session = it->second;
    return true;
}

int32_t UdmfFuseSessionManager::Activate(
    const std::string &sessionId, uint32_t targetTokenId, int32_t targetUid, int32_t targetGid, std::string &uri)
{
    if (targetTokenId == 0 || targetUid < 0 || targetGid < 0) {
        return -EINVAL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return -ESTALE;
    }
    if (it->second.state == State::ACTIVE) {
        if (it->second.targetTokenId != targetTokenId || it->second.targetUid != targetUid) {
            return -EACCES;
        }
        uri = "file://" + GetAppMountPoint(it->second.userId) + "/" + it->second.alias + "/" + it->second.root.name;
        return 0;
    }
    if (it->second.state != State::PENDING_DROP) {
        return -ESTALE;
    }
    auto sourceCount = activeSourceSessionCounts_.find(it->second.sourceTokenId);
    uint32_t sourceActiveCount = sourceCount == activeSourceSessionCounts_.end() ? 0 : sourceCount->second;
    if (activeSessionCount_ >= MAX_ACTIVE_SESSIONS || sourceActiveCount >= MAX_ACTIVE_SESSIONS_PER_SOURCE) {
        ZLOGW("Reject virtual entry activation because active quota is exhausted, active:%{public}u, "
              "sourceActive:%{public}u",
            activeSessionCount_, sourceActiveCount);
        return -EAGAIN;
    }
    int32_t ret = MountUserLocked(it->second.userId);
    if (ret != 0) {
        return ret;
    }
    auto controller = controllers_.find(it->second.userId);
    if (controller == controllers_.end()) {
        return -ENODEV;
    }
    it->second.alias = GenerateAlias();
    if (it->second.alias.empty()) {
        TryUnmountUserLocked(it->second.userId);
        return -EIO;
    }
    std::string relativePath;
    UdmfFuseController::SessionOptions options{ sessionId, it->second.alias, it->second.root, it->second.provider,
        static_cast<uid_t>(targetUid), static_cast<gid_t>(targetGid) };
    ret = controller->second->AddSession(options, relativePath);
    if (ret != 0) {
        TryUnmountUserLocked(it->second.userId);
        return ret;
    }
    it->second.targetTokenId = targetTokenId;
    it->second.targetUid = targetUid;
    it->second.targetGid = targetGid;
    it->second.state = State::ACTIVE;
    DecreasePendingSessionLocked(it->second.sourceTokenId);
    ++activeSessionCount_;
    ++activeSourceSessionCounts_[it->second.sourceTokenId];
    ++activeSessionCounts_[it->second.userId];
    if (executor_ != nullptr) {
        uint64_t generation = it->second.generation;
        it->second.expiryTask = executor_->Schedule(ACTIVE_SESSION_LEASE,
            [sessionId, generation] { UdmfFuseSessionManager::GetInstance().Expire(sessionId, generation); });
        ScheduleCleanupTaskLocked(sessionId, it->second, INITIAL_OPEN_TIMEOUT);
    }
    uri = "file://" + GetAppMountPoint(it->second.userId) + "/" + relativePath;
    return 0;
}

int32_t UdmfFuseSessionManager::AcquireOpen(const std::string &sessionId, int32_t callingUid)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end() || it->second.state != State::ACTIVE) {
        return -ESTALE;
    }
    if (callingUid < 0 || callingUid != it->second.targetUid) {
        return -EACCES;
    }
    CancelCleanupTaskLocked(it->second);
    ++it->second.openCount;
    return 0;
}

void UdmfFuseSessionManager::ReleaseOpen(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end() || it->second.openCount == 0) {
        return;
    }
    --it->second.openCount;
    if (it->second.openCount != 0) {
        return;
    }
    if (it->second.state == State::ACTIVE) {
        ScheduleCleanupTaskLocked(sessionId, it->second, IDLE_SESSION_TIMEOUT);
        return;
    }
    if (it->second.state == State::DRAINING) {
        int32_t userId = it->second.userId;
        auto controller = controllers_.find(userId);
        if (controller != controllers_.end()) {
            controller->second->RemoveSession(sessionId);
        }
        DecreaseActiveSessionLocked(userId, it->second.sourceTokenId);
        sessions_.erase(it);
        if (executor_ != nullptr) {
            (void)executor_->Execute([userId] { UdmfFuseSessionManager::GetInstance().TryUnmountUser(userId); });
        } else {
            ZLOGW("Delay unmount because executor is unavailable, userId:%{public}d", userId);
        }
    }
}

void UdmfFuseSessionManager::Remove(const std::string &sessionId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(sessionId);
    if (it == sessions_.end()) {
        return;
    }
    int32_t userId = it->second.userId;
    uint32_t sourceTokenId = it->second.sourceTokenId;
    bool wasPending = it->second.state == State::PENDING_DROP;
    if (executor_ != nullptr && it->second.expiryTask != ExecutorPool::INVALID_TASK_ID) {
        (void)executor_->Remove(it->second.expiryTask, false);
    }
    CancelCleanupTaskLocked(it->second);
    bool canRemoveDeathRecipient = it->second.provider != nullptr && it->second.deathRecipient != nullptr &&
                                   !it->second.provider->IsObjectDead();
    if (canRemoveDeathRecipient) {
        (void)it->second.provider->RemoveDeathRecipient(it->second.deathRecipient);
    }
    it->second.deathRecipient = nullptr;
    it->second.expiryTask = ExecutorPool::INVALID_TASK_ID;
    if (!wasPending && it->second.openCount != 0) {
        it->second.state = State::DRAINING;
        return;
    }
    auto controller = controllers_.find(userId);
    if (controller != controllers_.end()) {
        controller->second->RemoveSession(sessionId);
    }
    sessions_.erase(it);
    if (wasPending) {
        DecreasePendingSessionLocked(sourceTokenId);
    } else {
        DecreaseActiveSessionLocked(userId, sourceTokenId);
    }
    TryUnmountUserLocked(userId);
}

void UdmfFuseSessionManager::Expire(const std::string &sessionId, uint64_t generation)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(sessionId);
        if (it == sessions_.end() || it->second.generation != generation) {
            return;
        }
        it->second.expiryTask = ExecutorPool::INVALID_TASK_ID;
    }
    Remove(sessionId);
}

std::string UdmfFuseSessionManager::GetMountPoint(int32_t userId)
{
    return std::string(UDMF_FUSE_MOUNT_PREFIX) + std::to_string(userId) + UDMF_FUSE_MOUNT_SUFFIX;
}

std::string UdmfFuseSessionManager::GetAppMountPoint(int32_t)
{
    return UDMF_FUSE_APP_MOUNT_POINT;
}

bool UdmfFuseSessionManager::IsValid(const VirtualEntry &entry)
{
    uint32_t count = 0;
    return IsValidEntry(entry, 0, count);
}

bool UdmfFuseSessionManager::HasActiveSessionLocked(int32_t userId) const
{
    auto it = activeSessionCounts_.find(userId);
    return it != activeSessionCounts_.end() && it->second != 0;
}

void UdmfFuseSessionManager::DecreasePendingSessionLocked(uint32_t sourceTokenId)
{
    auto count = pendingSourceSessionCounts_.find(sourceTokenId);
    if (count == pendingSourceSessionCounts_.end()) {
        return;
    }
    if (pendingSessionCount_ > 0) {
        --pendingSessionCount_;
    }
    if (count->second > 1) {
        --count->second;
        return;
    }
    pendingSourceSessionCounts_.erase(count);
}

void UdmfFuseSessionManager::DecreaseActiveSessionLocked(int32_t userId, uint32_t sourceTokenId)
{
    auto sourceCount = activeSourceSessionCounts_.find(sourceTokenId);
    auto userCount = activeSessionCounts_.find(userId);
    if (sourceCount == activeSourceSessionCounts_.end() || userCount == activeSessionCounts_.end()) {
        return;
    }
    if (activeSessionCount_ > 0) {
        --activeSessionCount_;
    }
    if (sourceCount->second > 1) {
        --sourceCount->second;
    } else {
        activeSourceSessionCounts_.erase(sourceCount);
    }
    if (userCount->second > 1) {
        --userCount->second;
        return;
    }
    activeSessionCounts_.erase(userCount);
}

void UdmfFuseSessionManager::CancelCleanupTaskLocked(SessionInfo &session)
{
    if (executor_ != nullptr && session.cleanupTask != ExecutorPool::INVALID_TASK_ID) {
        (void)executor_->Remove(session.cleanupTask, false);
    }
    session.cleanupTask = ExecutorPool::INVALID_TASK_ID;
}

void UdmfFuseSessionManager::ScheduleCleanupTaskLocked(
    const std::string &sessionId, SessionInfo &session, const std::chrono::seconds &delay)
{
    CancelCleanupTaskLocked(session);
    if (executor_ == nullptr) {
        return;
    }
    uint64_t generation = session.generation;
    session.cleanupTask = executor_->Schedule(delay,
        [sessionId, generation] { UdmfFuseSessionManager::GetInstance().CleanupInactive(sessionId, generation); });
    if (session.cleanupTask == ExecutorPool::INVALID_TASK_ID) {
        ZLOGW("Schedule virtual entry cleanup task failed");
    }
}

void UdmfFuseSessionManager::CleanupInactive(const std::string &sessionId, uint64_t generation)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sessions_.find(sessionId);
        if (it == sessions_.end() || it->second.generation != generation) {
            return;
        }
        it->second.cleanupTask = ExecutorPool::INVALID_TASK_ID;
        if (it->second.state != State::ACTIVE || it->second.openCount != 0) {
            return;
        }
    }
    ZLOGI("Clean inactive virtual entry session");
    Remove(sessionId);
}

int32_t UdmfFuseSessionManager::MountUserLocked(int32_t userId)
{
    if (controllers_.find(userId) != controllers_.end()) {
        return 0;
    }
    std::string mountPoint = GetMountPoint(userId);
    int fuseFd = -1;
    int32_t ret = UdmfFuseMountAdapter::Mount(userId, mountPoint, fuseFd);
    if (ret != 0) {
        return ret;
    }
    auto controller = std::make_shared<UdmfFuseController>(userId);
    ret = controller->Start(fuseFd);
    if (ret != 0) {
        (void)UdmfFuseMountAdapter::Unmount(userId, mountPoint);
        return ret;
    }
    controllers_.emplace(userId, std::move(controller));
    return 0;
}

void UdmfFuseSessionManager::TryUnmountUserLocked(int32_t userId)
{
    if (HasActiveSessionLocked(userId)) {
        return;
    }
    auto controller = controllers_.find(userId);
    if (controller == controllers_.end()) {
        return;
    }
    controller->second->Stop();
    if (UdmfFuseMountAdapter::Unmount(userId, GetMountPoint(userId)) != 0) {
        ZLOGW("Unmount UDMF FUSE failed, userId:%{public}d", userId);
        return;
    }
    controllers_.erase(controller);
}

void UdmfFuseSessionManager::TryUnmountUser(int32_t userId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    TryUnmountUserLocked(userId);
}
} // namespace OHOS::UDMF
