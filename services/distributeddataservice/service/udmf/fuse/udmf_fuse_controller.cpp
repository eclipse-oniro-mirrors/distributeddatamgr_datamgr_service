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

#include "udmf_fuse_controller.h"

#include <fcntl.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cinttypes>
#include <deque>
#include <limits>
#include <unordered_set>

#include "log_print.h"
#include "udmf_fuse_session_manager.h"
#include "virtual_entry_provider.h"
#include "virtual_entry_provider_proxy.h"
#include "virtual_entry_read_callback_stub.h"

namespace OHOS::UDMF {
namespace {
constexpr double ATTR_TIMEOUT_SECONDS = 60.0;
constexpr size_t DIRECTORY_READ_BYTES = 64 * 1024;
constexpr size_t PROVIDER_BLOCK_BYTES = 5 * 1024 * 1024;
constexpr size_t MAX_CACHE_BYTES = 40 * 1024 * 1024;
constexpr size_t MAX_CONTROLLER_CACHE_BYTES = 3 * PROVIDER_BLOCK_BYTES;
constexpr unsigned long FUSE_STAT_BLOCK_BYTES = 4096;
constexpr unsigned long MAX_FILE_NAME_BYTES = 255;
constexpr int32_t PROVIDER_READ_MAX_ATTEMPTS = 3;
constexpr size_t MAX_PROVIDER_READS = 3;
constexpr size_t MAX_READS_PER_PROVIDER = MAX_PROVIDER_READS;
constexpr int32_t MAX_FUSE_THREADS = 16;
constexpr uint32_t PROVIDER_TIMEOUT_THRESHOLD = 3;
constexpr nfds_t FUSE_POLL_FD_COUNT = 2;
constexpr int64_t BYTES_PER_BLOCK = 512;
constexpr int64_t MILLISECONDS_PER_SECOND = 1000;
constexpr int64_t NANOSECONDS_PER_MILLISECOND = 1000000;
constexpr int32_t FUSE_EMPTY_READ_RETRY_LIMIT = 3;
constexpr mode_t ROOT_DIRECTORY_MODE = 0555;
constexpr mode_t SESSION_DIRECTORY_MODE = 0500;
constexpr mode_t VIRTUAL_FILE_MODE = 0400;
constexpr nlink_t DIRECTORY_LINK_COUNT = 2;
constexpr nlink_t FILE_LINK_COUNT = 1;
constexpr char FUSE_SERVICE_NAME[] = "udmf_fuse";
constexpr std::chrono::seconds FUSE_INIT_TIMEOUT(3);
constexpr std::chrono::seconds BLOCK_LOAD_TIMEOUT(30);
constexpr std::chrono::seconds PROVIDER_CIRCUIT_COOLDOWN(30);
constexpr std::chrono::milliseconds PROVIDER_RETRY_INTERVAL(50);

bool IsTransientReadError(int32_t status)
{
    return status == -EAGAIN || status == -ETIMEDOUT || status == -EINTR;
}

int ToFuseError(int32_t status)
{
    if (status == -ETIMEDOUT) {
        return ETIMEDOUT;
    }
    if (status == -ECANCELED) {
        return ECANCELED;
    }
    if (status == -EAGAIN || status == -ENOENT || status == -EINVAL || status == -EACCES || status == -ESTALE) {
        return -status;
    }
    return EIO;
}

class FuseCacheBudget final {
public:
    static FuseCacheBudget &GetInstance()
    {
        static FuseCacheBudget budget;
        return budget;
    }

    bool TryReserve(size_t bytes)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cachedBytes_ > MAX_CACHE_BYTES || bytes > MAX_CACHE_BYTES - cachedBytes_) {
            return false;
        }
        cachedBytes_ += bytes;
        return true;
    }

    void Release(size_t bytes)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cachedBytes_ = bytes > cachedBytes_ ? 0 : cachedBytes_ - bytes;
    }

private:
    std::mutex mutex_;
    size_t cachedBytes_ = 0;
};

} // namespace

struct UdmfFuseController::ProviderGate {
    struct State {
        sptr<IRemoteObject> provider;
        size_t inFlight = 0;
        uint32_t consecutiveTimeouts = 0;
        std::chrono::steady_clock::time_point openUntil;
        std::chrono::steady_clock::time_point lastTimeout;
    };

    struct Waiter {
        uint64_t ticket = 0;
        std::string sessionId;
    };

    int32_t Acquire(const sptr<IRemoteObject> &provider, const std::string &sessionId,
        const std::chrono::steady_clock::time_point &deadline)
    {
        if (provider == nullptr || sessionId.empty()) {
            return -EPIPE;
        }
        std::unique_lock<std::mutex> lock(mutex);
        const auto *providerKey = provider.GetRefPtr();
        uint64_t ticket = nextTicket++;
        waiters.push_back({ ticket, sessionId });
        while (true) {
            auto now = std::chrono::steady_clock::now();
            ClearRecoveredProvidersLocked(now);
            auto state = states.find(providerKey);
            if (state != states.end() && state->second.openUntil > now) {
                RemoveWaiterLocked(ticket);
                condition.notify_all();
                return -ETIMEDOUT;
            }
            size_t providerInFlight = state == states.end() ? 0 : state->second.inFlight;
            if (totalInFlight < MAX_PROVIDER_READS && providerInFlight < MAX_READS_PER_PROVIDER &&
                IsNextWaiterLocked(ticket)) {
                auto &providerState = states[providerKey];
                providerState.provider = provider;
                ++providerState.inFlight;
                ++sessionInFlight[sessionId];
                ++totalInFlight;
                RemoveWaiterLocked(ticket);
                condition.notify_all();
                return 0;
            }
            if (condition.wait_until(lock, deadline) == std::cv_status::timeout) {
                RemoveWaiterLocked(ticket);
                condition.notify_all();
                return -ETIMEDOUT;
            }
        }
    }

    void RecordTimeout(const sptr<IRemoteObject> &provider)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = states.find(provider.GetRefPtr());
        if (it == states.end()) {
            return;
        }
        auto &state = it->second;
        ++state.consecutiveTimeouts;
        state.lastTimeout = std::chrono::steady_clock::now();
        if (state.consecutiveTimeouts >= PROVIDER_TIMEOUT_THRESHOLD) {
            state.openUntil = std::chrono::steady_clock::now() + PROVIDER_CIRCUIT_COOLDOWN;
        }
    }

    void Release(const sptr<IRemoteObject> &provider, const std::string &sessionId, bool responsive)
    {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = states.find(provider.GetRefPtr());
        if (it == states.end()) {
            return;
        }
        auto &state = it->second;
        if (state.inFlight > 0) {
            --state.inFlight;
            --totalInFlight;
        }
        auto session = sessionInFlight.find(sessionId);
        if (session != sessionInFlight.end()) {
            if (session->second > 1) {
                --session->second;
            } else {
                sessionInFlight.erase(session);
            }
        }
        if (responsive) {
            state.consecutiveTimeouts = 0;
            state.openUntil = {};
        }
        if (state.inFlight == 0 && state.consecutiveTimeouts == 0) {
            states.erase(it);
        }
        condition.notify_all();
    }

    void ClearRecoveredProvidersLocked(const std::chrono::steady_clock::time_point &now)
    {
        for (auto it = states.begin(); it != states.end();) {
            const auto &state = it->second;
            if (state.inFlight == 0 && state.lastTimeout != std::chrono::steady_clock::time_point{} &&
                now - state.lastTimeout >= PROVIDER_CIRCUIT_COOLDOWN) {
                it = states.erase(it);
                continue;
            }
            ++it;
        }
    }

    bool IsNextWaiterLocked(uint64_t ticket) const
    {
        bool hasUnservedSession = false;
        for (const auto &waiter : waiters) {
            if (sessionInFlight.find(waiter.sessionId) == sessionInFlight.end()) {
                hasUnservedSession = true;
                break;
            }
        }
        for (const auto &waiter : waiters) {
            bool sessionHasSlot = sessionInFlight.find(waiter.sessionId) != sessionInFlight.end();
            if (hasUnservedSession && sessionHasSlot) {
                continue;
            }
            return waiter.ticket == ticket;
        }
        return false;
    }

    void RemoveWaiterLocked(uint64_t ticket)
    {
        auto waiter = std::find_if(
            waiters.begin(), waiters.end(), [ticket](const Waiter &item) { return item.ticket == ticket; });
        if (waiter != waiters.end()) {
            waiters.erase(waiter);
        }
    }

    std::mutex mutex;
    std::condition_variable condition;
    size_t totalInFlight = 0;
    uint64_t nextTicket = 0;
    std::unordered_map<const IRemoteObject *, State> states;
    std::unordered_map<std::string, size_t> sessionInFlight;
    std::deque<Waiter> waiters;
};

class UdmfFuseController::ProviderReadCallback final : public VirtualEntryReadCallbackStub {
public:
    struct Result {
        std::mutex mutex;
        std::condition_variable condition;
        bool done = false;
        bool timedOut = false;
        int32_t status = -EIO;
        std::vector<uint8_t> bytes;
    };

    ProviderReadCallback(std::shared_ptr<Result> result, std::shared_ptr<ProviderGate> gate,
        sptr<IRemoteObject> provider, std::string sessionId, size_t maxLength)
        : result_(std::move(result)), gate_(std::move(gate)), provider_(provider), sessionId_(std::move(sessionId)),
          maxLength_(maxLength)
    {
    }

    ~ProviderReadCallback() override
    {
        Release(false);
    }

    int32_t OnResult(int32_t status, const std::vector<uint8_t> &data) override
    {
        bool responsive = false;
        {
            std::lock_guard<std::mutex> lock(result_->mutex);
            if (result_->done) {
                return 0;
            }
            result_->done = true;
            responsive = !result_->timedOut;
            if (responsive) {
                result_->status = data.size() > maxLength_ ? -EIO : status;
                if (result_->status == 0) {
                    result_->bytes = data;
                }
            }
        }
        Release(responsive);
        result_->condition.notify_all();
        return 0;
    }

    void RecordTimeout()
    {
        gate_->RecordTimeout(provider_);
    }

private:
    void Release(bool responsive)
    {
        bool expected = false;
        if (released_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
            gate_->Release(provider_, sessionId_, responsive);
        }
    }

    const std::shared_ptr<Result> result_;
    const std::shared_ptr<ProviderGate> gate_;
    const sptr<IRemoteObject> provider_;
    const std::string sessionId_;
    const size_t maxLength_ = 0;
    std::atomic<bool> released_{ false };
};

UdmfFuseController::UdmfFuseController(int32_t userId) : userId_(userId)
{
    static std::shared_ptr<ProviderGate> globalProviderGate = std::make_shared<ProviderGate>();
    providerGate_ = globalProviderGate;
    VirtualEntryProviderProxy::EnsureRegistered();
}

UdmfFuseController::~UdmfFuseController()
{
    Stop();
}

int32_t UdmfFuseController::CreateFuseSession(int fuseFd, struct fuse_session *&session)
{
    struct fuse_args args = FUSE_ARGS_INIT(0, nullptr);
    if (fuse_opt_add_arg(&args, FUSE_SERVICE_NAME) != 0) {
        fuse_opt_free_args(&args);
        return -ENOMEM;
    }
    struct fuse_lowlevel_ops operations {};
    operations.init = Init;
    operations.lookup = Lookup;
    operations.forget = Forget;
    operations.getattr = GetAttr;
    operations.access = Access;
    operations.statfs = StatFs;
    operations.opendir = OpenDir;
    operations.readdir = ReadDir;
    operations.readdirplus = ReadDirPlus;
    operations.releasedir = ReleaseDir;
    operations.open = Open;
    operations.read = Read;
    operations.flush = Flush;
    operations.fsync = Fsync;
    operations.lseek = Lseek;
    operations.release = Release;
    session = fuse_session_new(&args, &operations, sizeof(operations), this);
    fuse_opt_free_args(&args);
    if (session == nullptr) {
        return -ENOMEM;
    }
    struct fuse_custom_io customIo {};
    customIo.read = ReadFuseFd;
    customIo.writev = WriteFuseFd;
    int32_t ret = fuse_session_custom_io(session, &customIo, sizeof(customIo), fuseFd);
    if (ret != 0) {
        fuse_session_destroy(session);
        session = nullptr;
    }
    return ret;
}

int32_t UdmfFuseController::Start(int fuseFd)
{
    if (fuseFd < 0) {
        return -EBADF;
    }
    int wakeFd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (wakeFd < 0) {
        (void)close(fuseFd);
        return -errno;
    }
    struct fuse_session *session = nullptr;
    int32_t ret = CreateFuseSession(fuseFd, session);
    if (ret != 0) {
        (void)close(wakeFd);
        (void)close(fuseFd);
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fuseSession_ != nullptr) {
            fuse_session_destroy(session);
            (void)close(wakeFd);
            return -EALREADY;
        }
        Node root;
        root.inode = FUSE_ROOT_ID;
        root.parent = FUSE_ROOT_ID;
        root.synthetic = true;
        root.entry.name = "/";
        root.entry.type = VirtualEntryType::DIRECTORY;
        nodes_.emplace(FUSE_ROOT_ID, std::move(root));
        fuseSession_ = session;
        wakeFd_ = wakeFd;
        loopState_ = LoopState::STARTING;
        loopResult_ = 0;
    }
    loopThread_ = std::thread(&UdmfFuseController::LoopMain, this);
    int32_t startResult = 0;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        bool initialized =
            loopCondition_.wait_for(lock, FUSE_INIT_TIMEOUT, [this] { return loopState_ != LoopState::STARTING; });
        if (!initialized) {
            startResult = -ETIMEDOUT;
        } else if (loopState_ != LoopState::INITIALIZED) {
            startResult = loopResult_ == 0 ? -EIO : loopResult_;
        }
    }
    if (startResult != 0) {
        ZLOGE("Start UDMF FUSE loop failed, userId:%{public}d ret:%{public}d", userId_, startResult);
        Stop();
    }
    return startResult;
}

void UdmfFuseController::Stop()
{
    struct fuse_session *session = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        session = fuseSession_;
        if (session != nullptr) {
            loopState_ = LoopState::STOPPING;
        }
    }
    if (session == nullptr) {
        std::lock_guard<std::mutex> lock(mutex_);
        ClearBlocksLocked();
        return;
    }
    fuse_session_exit(session);
    WakeLoop();
    if (loopThread_.joinable()) {
        loopThread_.join();
    }
    fuse_session_destroy(session);
    int wakeFd = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        fuseSession_ = nullptr;
        wakeFd = wakeFd_;
        wakeFd_ = -1;
        ClearBlocksLocked();
        sessions_.clear();
        nodes_.clear();
        loopState_ = LoopState::IDLE;
        loopResult_ = 0;
    }
    if (wakeFd >= 0) {
        (void)close(wakeFd);
    }
}

int32_t UdmfFuseController::AddTreeLocked(
    fuse_ino_t parent, const VirtualEntry &entry, Session &session, fuse_ino_t &inode)
{
    auto parentIt = nodes_.find(parent);
    if (parentIt == nodes_.end() || parentIt->second.entry.type != VirtualEntryType::DIRECTORY) {
        return -ENOENT;
    }
    if (parentIt->second.childrenByName.find(entry.name) != parentIt->second.childrenByName.end()) {
        return -EEXIST;
    }
    inode = nextInode_.fetch_add(1, std::memory_order_relaxed);
    Node node;
    node.inode = inode;
    node.parent = parent;
    node.sessionId = session.sessionId;
    node.entry = entry;
    node.entry.subItems.clear();
    if (entry.type == VirtualEntryType::DIRECTORY) {
        node.children.reserve(entry.subItems.size());
        node.childrenByName.reserve(entry.subItems.size());
    }
    node.targetUid = session.targetUid;
    node.targetGid = session.targetGid;
    node.statAttempted = entry.type != VirtualEntryType::FILE || entry.size >= 0;
    // unordered_map::emplace may rehash and invalidate parentIt.
    parentIt->second.children.push_back(inode);
    parentIt->second.childrenByName.emplace(entry.name, inode);
    nodes_.emplace(inode, node);
    session.nodes.push_back(inode);
    if (entry.type == VirtualEntryType::FILE) {
        session.fileIds.push_back(entry.id);
        return 0;
    }
    for (const auto &child : entry.subItems) {
        fuse_ino_t childInode = 0;
        int32_t ret = AddTreeLocked(inode, child, session, childInode);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

int32_t UdmfFuseController::AddSession(const SessionOptions &options, std::string &relativePath)
{
    if (options.sessionId.empty() || options.alias.empty() || options.provider == nullptr) {
        return -EINVAL;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (fuseSession_ == nullptr || loopState_ != LoopState::INITIALIZED ||
        sessions_.find(options.sessionId) != sessions_.end()) {
        return fuseSession_ == nullptr || loopState_ != LoopState::INITIALIZED ? -ENODEV : -EEXIST;
    }
    Session session;
    session.sessionId = options.sessionId;
    session.alias = options.alias;
    session.provider = options.provider;
    session.targetUid = options.targetUid;
    session.targetGid = options.targetGid;
    VirtualEntry aliasEntry;
    aliasEntry.name = options.alias;
    aliasEntry.type = VirtualEntryType::DIRECTORY;
    fuse_ino_t aliasInode = 0;
    int32_t ret = AddTreeLocked(FUSE_ROOT_ID, aliasEntry, session, aliasInode);
    if (ret == 0) {
        fuse_ino_t rootInode = 0;
        ret = AddTreeLocked(aliasInode, options.root, session, rootInode);
    }
    if (ret != 0) {
        for (auto inode : session.nodes) {
            nodes_.erase(inode);
        }
        auto rootNode = nodes_.find(FUSE_ROOT_ID);
        if (rootNode != nodes_.end()) {
            rootNode->second.children.erase(
                std::remove(rootNode->second.children.begin(), rootNode->second.children.end(), aliasInode),
                rootNode->second.children.end());
            auto alias = rootNode->second.childrenByName.find(options.alias);
            if (alias != rootNode->second.childrenByName.end() && alias->second == aliasInode) {
                rootNode->second.childrenByName.erase(alias);
            }
        }
        return ret;
    }
    sessions_.emplace(options.sessionId, std::move(session));
    relativePath = options.alias + "/" + options.root.name;
    return 0;
}

void UdmfFuseController::RemoveSession(const std::string &sessionId)
{
    sptr<IRemoteObject> provider;
    std::vector<std::string> fileIds;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto session = sessions_.find(sessionId);
        if (session == sessions_.end()) {
            return;
        }
        provider = session->second.provider;
        fileIds = session->second.fileIds;
        RemoveBlocksLocked(session->second.nodes);
        for (auto inode : session->second.nodes) {
            auto node = nodes_.find(inode);
            if (node != nodes_.end()) {
                auto parent = nodes_.find(node->second.parent);
                if (parent != nodes_.end()) {
                    parent->second.children.erase(
                        std::remove(parent->second.children.begin(), parent->second.children.end(), inode),
                        parent->second.children.end());
                    auto child = parent->second.childrenByName.find(node->second.entry.name);
                    if (child != parent->second.childrenByName.end() && child->second == inode) {
                        parent->second.childrenByName.erase(child);
                    }
                }
                nodes_.erase(node);
            }
        }
        sessions_.erase(session);
    }
    // Cancel is best-effort. The provider side has its own timeout and will
    // reject late completions after the session disappears.
    ProviderCancel(provider, fileIds);
}

bool UdmfFuseController::IsAllowed(fuse_req_t req, const Node &node) const
{
    const struct fuse_ctx *context = fuse_req_ctx(req);
    if (context == nullptr) {
        return false;
    }
    return IsUidAllowed(context->uid, node);
}

bool UdmfFuseController::IsUidAllowed(uid_t callingUid, const Node &node) const
{
    // The shared root must remain searchable so applications can resolve an
    // authorized alias. Every session node is restricted to the drop target.
    return node.inode == FUSE_ROOT_ID || callingUid == node.targetUid;
}

int32_t UdmfFuseController::CheckAccess(uid_t callingUid, const Node &node, int mask) const
{
    constexpr int validMask = R_OK | W_OK | X_OK;
    if ((mask & ~validMask) != 0) {
        return -EINVAL;
    }
    if (!IsUidAllowed(callingUid, node)) {
        return -EACCES;
    }
    if ((mask & W_OK) != 0) {
        return -EROFS;
    }
    if ((mask & X_OK) != 0 && node.entry.type != VirtualEntryType::DIRECTORY && !node.synthetic) {
        return -EACCES;
    }
    return 0;
}

int32_t UdmfFuseController::GetSeekResult(const Node &node, off_t offset, int whence, off_t &result)
{
    if (node.entry.type != VirtualEntryType::FILE) {
        return -EISDIR;
    }
    if (offset < 0) {
        return -EINVAL;
    }
    if (node.entry.size < 0 || node.entry.size > std::numeric_limits<off_t>::max()) {
        return -EIO;
    }
    off_t fileSize = static_cast<off_t>(node.entry.size);
    if (offset >= fileSize) {
        return -ENXIO;
    }
    if (whence == SEEK_DATA) {
        result = offset;
        return 0;
    }
    if (whence == SEEK_HOLE) {
        result = fileSize;
        return 0;
    }
    return -EINVAL;
}

void UdmfFuseController::FillStatFs(uid_t callingUid, struct statvfs &stat) const
{
    stat = {};
    stat.f_bsize = FUSE_STAT_BLOCK_BYTES;
    stat.f_frsize = FUSE_STAT_BLOCK_BYTES;
    stat.f_flag = ST_RDONLY;
    stat.f_namemax = MAX_FILE_NAME_BYTES;
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto &[inode, node] : nodes_) {
        if (inode != FUSE_ROOT_ID && node.targetUid != callingUid) {
            continue;
        }
        if (stat.f_files < std::numeric_limits<fsfilcnt_t>::max()) {
            ++stat.f_files;
        }
        if (node.entry.type != VirtualEntryType::FILE || node.entry.size <= 0) {
            continue;
        }
        auto size = static_cast<uint64_t>(node.entry.size);
        auto blocks = static_cast<fsblkcnt_t>((size + FUSE_STAT_BLOCK_BYTES - 1) / FUSE_STAT_BLOCK_BYTES);
        if (blocks > std::numeric_limits<fsblkcnt_t>::max() - stat.f_blocks) {
            stat.f_blocks = std::numeric_limits<fsblkcnt_t>::max();
        } else {
            stat.f_blocks += blocks;
        }
    }
}

bool UdmfFuseController::GetNode(fuse_ino_t inode, Node &node, sptr<IRemoteObject> &provider) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(inode);
    if (it == nodes_.end()) {
        return false;
    }
    node = it->second;
    if (!node.sessionId.empty()) {
        auto session = sessions_.find(node.sessionId);
        if (session == sessions_.end()) {
            return false;
        }
        provider = session->second.provider;
    }
    return true;
}

void UdmfFuseController::FillAttr(const Node &node, struct stat &attr) const
{
    attr = {};
    attr.st_ino = node.inode;
    attr.st_uid = node.targetUid;
    attr.st_gid = node.targetGid;
    attr.st_mtim.tv_sec = node.entry.modifyTime / MILLISECONDS_PER_SECOND;
    attr.st_mtim.tv_nsec = (node.entry.modifyTime % MILLISECONDS_PER_SECOND) * NANOSECONDS_PER_MILLISECOND;
    if (node.entry.type == VirtualEntryType::DIRECTORY || node.synthetic) {
        // The shared FUSE root must be searchable before low-level lookup can
        // filter aliases by target UID. Per-session directories stay private.
        attr.st_mode = S_IFDIR | (node.inode == FUSE_ROOT_ID ? ROOT_DIRECTORY_MODE : SESSION_DIRECTORY_MODE);
        attr.st_nlink = DIRECTORY_LINK_COUNT;
        return;
    }
    attr.st_mode = S_IFREG | VIRTUAL_FILE_MODE;
    attr.st_nlink = FILE_LINK_COUNT;
    attr.st_size = std::max<int64_t>(node.entry.size, 0);
    attr.st_blksize = PROVIDER_BLOCK_BYTES;
    attr.st_blocks = (attr.st_size + BYTES_PER_BLOCK - 1) / BYTES_PER_BLOCK;
}

void UdmfFuseController::Init(void *userdata, struct fuse_conn_info *connection)
{
    auto *controller = static_cast<UdmfFuseController *>(userdata);
    if (controller == nullptr || connection == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(controller->mutex_);
        if (controller->loopState_ != LoopState::STARTING) {
            return;
        }
        controller->loopState_ = LoopState::INITIALIZED;
    }
    controller->loopCondition_.notify_all();
    bool readdirPlus = (connection->want & FUSE_CAP_READDIRPLUS) != 0;
    ZLOGI("UDMF FUSE initialized, userId:%{public}d protocol:%{public}u.%{public}u readdirPlus:%{public}d",
        controller->userId_, connection->proto_major, connection->proto_minor, readdirPlus);
}

void UdmfFuseController::Lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    if (controller == nullptr || name == nullptr || name[0] == '\0') {
        fuse_reply_err(req, EINVAL);
        return;
    }
    Node child;
    int32_t error = 0;
    {
        std::lock_guard<std::mutex> lock(controller->mutex_);
        auto parentNode = controller->nodes_.find(parent);
        if (parentNode == controller->nodes_.end() || !controller->IsAllowed(req, parentNode->second)) {
            error = EACCES;
        } else {
            auto childIndex = parentNode->second.childrenByName.find(name);
            auto childNode = childIndex == parentNode->second.childrenByName.end()
                                 ? controller->nodes_.end()
                                 : controller->nodes_.find(childIndex->second);
            if (childNode == controller->nodes_.end() || !controller->IsAllowed(req, childNode->second)) {
                error = ENOENT;
            } else {
                child = childNode->second;
            }
        }
    }
    if (error != 0) {
        fuse_reply_err(req, error);
        return;
    }
    struct fuse_entry_param result {};
    result.ino = child.inode;
    controller->FillAttr(child, result.attr);
    result.attr_timeout = ATTR_TIMEOUT_SECONDS;
    result.entry_timeout = ATTR_TIMEOUT_SECONDS;
    fuse_reply_entry(req, &result);
}

void UdmfFuseController::Forget(fuse_req_t req, fuse_ino_t inode, uint64_t nlookup)
{
    (void)inode;
    (void)nlookup;
    fuse_reply_none(req);
}

void UdmfFuseController::GetAttr(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo)
{
    (void)fileInfo;
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, node, provider)) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    if (!controller->IsAllowed(req, node)) {
        fuse_reply_err(req, EACCES);
        return;
    }
    if (node.entry.type == VirtualEntryType::FILE && !node.statAttempted) {
        VirtualEntry actual;
        int32_t ret = ProviderStat(provider, node.entry.id, actual);
        if (ret != 0 && ret != -ENOSYS) {
            fuse_reply_err(req, ToFuseError(ret));
            return;
        }
        if (ret == 0 && actual.id != node.entry.id) {
            fuse_reply_err(req, EIO);
            return;
        }
        node.statAttempted = true;
        if (ret == 0) {
            node.entry.size = actual.size;
            node.entry.modifyTime = actual.modifyTime;
        }
        {
            std::lock_guard<std::mutex> lock(controller->mutex_);
            auto stored = controller->nodes_.find(inode);
            if (stored != controller->nodes_.end()) {
                stored->second.entry = node.entry;
                stored->second.statAttempted = true;
            }
        }
    }
    struct stat attr {};
    controller->FillAttr(node, attr);
    fuse_reply_attr(req, &attr, ATTR_TIMEOUT_SECONDS);
}

void UdmfFuseController::Access(fuse_req_t req, fuse_ino_t inode, int mask)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, node, provider)) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    const struct fuse_ctx *context = fuse_req_ctx(req);
    int32_t ret = context == nullptr ? -EACCES : controller->CheckAccess(context->uid, node, mask);
    fuse_reply_err(req, ret == 0 ? 0 : -ret);
}

void UdmfFuseController::StatFs(fuse_req_t req, fuse_ino_t inode)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    const struct fuse_ctx *context = fuse_req_ctx(req);
    if (controller == nullptr || context == nullptr) {
        fuse_reply_err(req, EACCES);
        return;
    }
    if (inode != 0) {
        Node node;
        sptr<IRemoteObject> provider;
        if (!controller->GetNode(inode, node, provider)) {
            fuse_reply_err(req, ENOENT);
            return;
        }
        if (!controller->IsUidAllowed(context->uid, node)) {
            fuse_reply_err(req, EACCES);
            return;
        }
    }
    struct statvfs stat {};
    controller->FillStatFs(context->uid, stat);
    fuse_reply_statfs(req, &stat);
}

void UdmfFuseController::OpenDir(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, node, provider) ||
        node.entry.type != VirtualEntryType::DIRECTORY) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    if (!controller->IsAllowed(req, node)) {
        fuse_reply_err(req, EACCES);
        return;
    }
    const struct fuse_ctx *context = fuse_req_ctx(req);
    if (!node.sessionId.empty()) {
        int32_t ret = UdmfFuseSessionManager::GetInstance().AcquireOpen(
            node.sessionId, context == nullptr ? -1 : static_cast<int32_t>(context->uid));
        if (ret != 0) {
            fuse_reply_err(req, ToFuseError(ret));
            return;
        }
    }
    fileInfo->fh = inode;
    fuse_reply_open(req, fileInfo);
}

void UdmfFuseController::ReadDir(
    fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
    (void)fileInfo;
    ReadDirectory(req, inode, size, offset, false);
}

void UdmfFuseController::ReadDirPlus(
    fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
    (void)fileInfo;
    ReadDirectory(req, inode, size, offset, true);
}

void UdmfFuseController::ReadDirectory(fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, bool plus)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node directory;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, directory, provider) ||
        directory.entry.type != VirtualEntryType::DIRECTORY) {
        fuse_reply_err(req, ENOTDIR);
        return;
    }
    if (!controller->IsAllowed(req, directory) || offset < 0) {
        fuse_reply_err(req, EACCES);
        return;
    }
    std::vector<Node> entries;
    Node dot = directory;
    dot.entry.name = ".";
    entries.push_back(dot);
    Node dotdot;
    sptr<IRemoteObject> ignored;
    if (!controller->GetNode(directory.parent, dotdot, ignored)) {
        dotdot = directory;
    }
    dotdot.entry.name = "..";
    entries.push_back(dotdot);
    {
        std::lock_guard<std::mutex> lock(controller->mutex_);
        for (auto childInode : directory.children) {
            auto child = controller->nodes_.find(childInode);
            if (inode != FUSE_ROOT_ID && child != controller->nodes_.end() &&
                controller->IsAllowed(req, child->second)) {
                entries.push_back(child->second);
            }
        }
    }
    size_t bufferSize = std::min(size, DIRECTORY_READ_BYTES);
    std::vector<char> buffer(bufferSize);
    size_t used = 0;
    for (size_t index = static_cast<size_t>(offset); index < entries.size(); ++index) {
        struct fuse_entry_param entry {};
        entry.ino = entries[index].inode;
        entry.attr_timeout = ATTR_TIMEOUT_SECONDS;
        entry.entry_timeout = ATTR_TIMEOUT_SECONDS;
        controller->FillAttr(entries[index], entry.attr);
        size_t needed =
            plus ? fuse_add_direntry_plus(req, nullptr, 0, entries[index].entry.name.c_str(), &entry, index + 1)
                 : fuse_add_direntry(req, nullptr, 0, entries[index].entry.name.c_str(), &entry.attr, index + 1);
        if (needed > bufferSize - used) {
            break;
        }
        if (plus) {
            (void)fuse_add_direntry_plus(
                req, buffer.data() + used, bufferSize - used, entries[index].entry.name.c_str(), &entry, index + 1);
        } else {
            (void)fuse_add_direntry(req, buffer.data() + used, bufferSize - used, entries[index].entry.name.c_str(),
                &entry.attr, index + 1);
        }
        used += needed;
    }
    fuse_reply_buf(req, buffer.data(), used);
}

void UdmfFuseController::ReleaseDir(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo)
{
    (void)fileInfo;
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller != nullptr && controller->GetNode(inode, node, provider) && !node.sessionId.empty()) {
        UdmfFuseSessionManager::GetInstance().ReleaseOpen(node.sessionId);
    }
    fuse_reply_err(req, 0);
}

void UdmfFuseController::Open(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, node, provider)) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    if (!controller->IsAllowed(req, node)) {
        fuse_reply_err(req, EACCES);
        return;
    }
    if (node.entry.type != VirtualEntryType::FILE) {
        fuse_reply_err(req, EISDIR);
        return;
    }
    if ((fileInfo->flags & O_ACCMODE) != O_RDONLY) {
        fuse_reply_err(req, EROFS);
        return;
    }
    const struct fuse_ctx *context = fuse_req_ctx(req);
    int32_t ret = UdmfFuseSessionManager::GetInstance().AcquireOpen(
        node.sessionId, context == nullptr ? -1 : static_cast<int32_t>(context->uid));
    if (ret != 0) {
        fuse_reply_err(req, ToFuseError(ret));
        return;
    }
    fileInfo->fh = inode;
    fileInfo->direct_io = 1;
    fuse_reply_open(req, fileInfo);
}

void UdmfFuseController::Read(
    fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, struct fuse_file_info *fileInfo)
{
    (void)fileInfo;
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, node, provider)) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    if (!controller->IsAllowed(req, node)) {
        fuse_reply_err(req, EACCES);
        return;
    }
    if (offset < 0 || node.entry.type != VirtualEntryType::FILE) {
        fuse_reply_err(req, EINVAL);
        return;
    }
    if (size == 0 || (node.entry.size >= 0 && offset >= node.entry.size)) {
        fuse_reply_buf(req, nullptr, 0);
        return;
    }
    if (node.entry.size < 0) {
        VirtualEntry actual;
        int32_t ret = ProviderStat(provider, node.entry.id, actual);
        if (ret != 0 || actual.id != node.entry.id || actual.size < 0) {
            fuse_reply_err(req, ToFuseError(ret == 0 ? -EIO : ret));
            return;
        }
        node.entry.size = actual.size;
        node.entry.modifyTime = actual.modifyTime;
        std::lock_guard<std::mutex> lock(controller->mutex_);
        auto stored = controller->nodes_.find(inode);
        if (stored != controller->nodes_.end()) {
            stored->second.entry = node.entry;
            stored->second.statAttempted = true;
        }
    }
    uint64_t available = static_cast<uint64_t>(node.entry.size - offset);
    size_t replySize = static_cast<size_t>(std::min<uint64_t>(size, available));
    std::vector<uint8_t> result(replySize);
    size_t copied = 0;
    while (copied < replySize) {
        uint64_t currentOffset = static_cast<uint64_t>(offset) + copied;
        uint64_t blockIndex = currentOffset / PROVIDER_BLOCK_BYTES;
        size_t offsetInBlock = static_cast<size_t>(currentOffset % PROVIDER_BLOCK_BYTES);
        BlockKey blockKey{ node.inode, blockIndex };
        std::shared_ptr<BlockEntry> block;
        int32_t ret = controller->GetOrLoadBlock(node, provider, blockIndex, block);
        if (ret != 0 || block == nullptr || offsetInBlock >= block->data.size()) {
            controller->ReleaseTransientBlock(blockKey, block);
            ZLOGE("Read virtual entry block failed, inode:%{public}" PRIu64 ", block:%{public}" PRIu64
                  ", ret:%{public}d",
                static_cast<uint64_t>(inode), blockIndex, ret);
            fuse_reply_err(req, ToFuseError(ret == 0 ? -EIO : ret));
            return;
        }
        size_t copySize = std::min(replySize - copied, block->data.size() - offsetInBlock);
        std::copy_n(block->data.data() + offsetInBlock, copySize, result.data() + copied);
        copied += copySize;
        controller->ReleaseTransientBlock(blockKey, block);
    }
    fuse_reply_buf(req, reinterpret_cast<const char *>(result.data()), result.size());
}

void UdmfFuseController::Flush(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, node, provider)) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    if (!controller->IsAllowed(req, node)) {
        fuse_reply_err(req, EACCES);
        return;
    }
    if (node.entry.type != VirtualEntryType::FILE) {
        fuse_reply_err(req, EISDIR);
        return;
    }
    fuse_reply_err(req, fileInfo == nullptr || fileInfo->fh != inode ? EBADF : 0);
}

void UdmfFuseController::Fsync(fuse_req_t req, fuse_ino_t inode, int dataSync, struct fuse_file_info *fileInfo)
{
    (void)dataSync;
    Flush(req, inode, fileInfo);
}

void UdmfFuseController::Lseek(
    fuse_req_t req, fuse_ino_t inode, off_t offset, int whence, struct fuse_file_info *fileInfo)
{
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller == nullptr || !controller->GetNode(inode, node, provider)) {
        fuse_reply_err(req, ENOENT);
        return;
    }
    if (!controller->IsAllowed(req, node)) {
        fuse_reply_err(req, EACCES);
        return;
    }
    if (fileInfo == nullptr || fileInfo->fh != inode) {
        fuse_reply_err(req, EBADF);
        return;
    }
    if (node.entry.type == VirtualEntryType::FILE && node.entry.size < 0) {
        VirtualEntry actual;
        int32_t ret = ProviderStat(provider, node.entry.id, actual);
        if (ret != 0 || actual.id != node.entry.id || actual.size < 0) {
            fuse_reply_err(req, ToFuseError(ret == 0 ? -EIO : ret));
            return;
        }
        node.entry.size = actual.size;
        node.entry.modifyTime = actual.modifyTime;
        std::lock_guard<std::mutex> lock(controller->mutex_);
        auto stored = controller->nodes_.find(inode);
        if (stored != controller->nodes_.end()) {
            stored->second.entry = node.entry;
            stored->second.statAttempted = true;
        }
    }
    off_t result = 0;
    int32_t ret = GetSeekResult(node, offset, whence, result);
    if (ret != 0) {
        fuse_reply_err(req, -ret);
        return;
    }
    fuse_reply_lseek(req, result);
}

void UdmfFuseController::Release(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo)
{
    (void)fileInfo;
    auto *controller = static_cast<UdmfFuseController *>(fuse_req_userdata(req));
    Node node;
    sptr<IRemoteObject> provider;
    if (controller != nullptr && controller->GetNode(inode, node, provider) && !node.sessionId.empty()) {
        UdmfFuseSessionManager::GetInstance().ReleaseOpen(node.sessionId);
    }
    fuse_reply_err(req, 0);
}

int32_t UdmfFuseController::ProviderStat(
    const sptr<IRemoteObject> &provider, const std::string &id, VirtualEntry &entry)
{
    auto virtualProvider = iface_cast<IVirtualEntryProvider>(provider);
    return virtualProvider == nullptr ? -EPIPE : virtualProvider->Stat(id, entry);
}

int32_t UdmfFuseController::ProviderRead(const sptr<IRemoteObject> &provider, const std::string &sessionId,
    const std::string &id, int64_t offset, int32_t length, const std::chrono::steady_clock::time_point &deadline,
    std::vector<uint8_t> &bytes)
{
    if (provider == nullptr || length < 0 || static_cast<size_t>(length) > PROVIDER_BLOCK_BYTES) {
        return -EINVAL;
    }
    int32_t ret = providerGate_->Acquire(provider, sessionId, deadline);
    if (ret != 0) {
        ZLOGW("Acquire virtual entry provider read slot failed, length:%{public}d, ret:%{public}d", length, ret);
        return ret;
    }
    auto result = std::make_shared<ProviderReadCallback::Result>();
    sptr<ProviderReadCallback> callback = new (std::nothrow)
        ProviderReadCallback(result, providerGate_, provider, sessionId, static_cast<size_t>(length));
    if (callback == nullptr) {
        providerGate_->Release(provider, sessionId, false);
        return -ENOMEM;
    }
    VirtualEntryProviderProxy providerProxy(provider);
    ret = providerProxy.ReadAsync(id, offset, length, callback->AsObject());
    if (ret != 0) {
        return ret;
    }
    std::unique_lock<std::mutex> lock(result->mutex);
    if (!result->condition.wait_until(lock, deadline, [&result] { return result->done; })) {
        result->timedOut = true;
        callback->RecordTimeout();
        ZLOGW("Virtual entry provider read timed out, offset:%{public}" PRId64 ", length:%{public}d", offset, length);
        return -ETIMEDOUT;
    }
    bytes = std::move(result->bytes);
    return result->status;
}

int32_t UdmfFuseController::GetOrLoadBlock(
    const Node &node, const sptr<IRemoteObject> &provider, uint64_t blockIndex, std::shared_ptr<BlockEntry> &block)
{
    if (node.entry.size < 0 || blockIndex > std::numeric_limits<uint64_t>::max() / PROVIDER_BLOCK_BYTES) {
        return -EINVAL;
    }
    uint64_t blockOffset = blockIndex * PROVIDER_BLOCK_BYTES;
    if (blockOffset >= static_cast<uint64_t>(node.entry.size)) {
        return -EINVAL;
    }
    BlockKey key{ node.inode, blockIndex };
    bool shouldLoad = false;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto it = blocks_.find(key);
        if (it == blocks_.end()) {
            block = std::make_shared<BlockEntry>();
            block->deadline = std::chrono::steady_clock::now() + BLOCK_LOAD_TIMEOUT;
            block->lastAccess = ++accessSequence_;
            blocks_.emplace(key, block);
            shouldLoad = true;
        } else {
            block = it->second;
            if (block->state == BlockState::LOADING && !block->condition.wait_until(lock, block->deadline,
                                                           [&block] { return block->state != BlockState::LOADING; })) {
                return -ETIMEDOUT;
            }
            if (block->state == BlockState::FAILED && IsTransientReadError(block->status)) {
                block = std::make_shared<BlockEntry>();
                block->deadline = std::chrono::steady_clock::now() + BLOCK_LOAD_TIMEOUT;
                block->lastAccess = ++accessSequence_;
                it->second = block;
                shouldLoad = true;
            }
        }
        if (!shouldLoad) {
            block->lastAccess = ++accessSequence_;
            return block->state == BlockState::READY ? 0 : block->status;
        }
    }

    uint64_t remaining = static_cast<uint64_t>(node.entry.size) - blockOffset;
    size_t expectedSize = static_cast<size_t>(std::min<uint64_t>(remaining, PROVIDER_BLOCK_BYTES));
    std::vector<uint8_t> bytes;
    bytes.reserve(expectedSize);
    int32_t ret = 0;
    while (bytes.size() < expectedSize) {
        if (std::chrono::steady_clock::now() >= block->deadline) {
            ret = -ETIMEDOUT;
            break;
        }
        size_t requestSize = expectedSize - bytes.size();
        std::vector<uint8_t> part;
        int32_t attempt = 0;
        do {
            ret = ProviderRead(provider, node.sessionId, node.entry.id,
                static_cast<int64_t>(blockOffset + bytes.size()), static_cast<int32_t>(requestSize), block->deadline,
                part);
            ++attempt;
            if (ret == 0 || !IsTransientReadError(ret) || attempt >= PROVIDER_READ_MAX_ATTEMPTS) {
                break;
            }
            ZLOGW("Retry virtual entry block read, inode:%{public}" PRIu64 ", block:%{public}" PRIu64
                  ", attempt:%{public}d, ret:%{public}d",
                static_cast<uint64_t>(node.inode), blockIndex, attempt, ret);
            auto now = std::chrono::steady_clock::now();
            if (now >= block->deadline) {
                ret = -ETIMEDOUT;
                break;
            }
            auto retryDelay = PROVIDER_RETRY_INTERVAL * attempt;
            std::unique_lock<std::mutex> lock(mutex_);
            block->condition.wait_until(lock, std::min(now + retryDelay, block->deadline),
                [&block] { return block->state == BlockState::CANCELED; });
            if (block->state == BlockState::CANCELED) {
                ret = -ECANCELED;
                break;
            }
            if (std::chrono::steady_clock::now() >= block->deadline) {
                ret = -ETIMEDOUT;
                break;
            }
            part.clear();
        } while (true);
        if (ret != 0) {
            break;
        }
        if (part.empty() || part.size() > requestSize) {
            ret = -EIO;
            break;
        }
        bytes.insert(bytes.end(), part.begin(), part.end());
    }

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = blocks_.find(key);
    if (it == blocks_.end() || it->second != block || block->state == BlockState::CANCELED) {
        block->state = BlockState::CANCELED;
        block->status = -ECANCELED;
        block->condition.notify_all();
        return -ECANCELED;
    }
    if (ret == 0) {
        block->data = std::move(bytes);
        block->state = BlockState::READY;
        block->status = 0;
        block->lastAccess = ++accessSequence_;
        EvictBlocksLocked(block->data.size());
        block->cacheReserved = FuseCacheBudget::GetInstance().TryReserve(block->data.size());
        while (!block->cacheReserved && EvictOldestBlockLocked()) {
            block->cacheReserved = FuseCacheBudget::GetInstance().TryReserve(block->data.size());
        }
        if (block->cacheReserved) {
            cachedBytes_ += block->data.size();
        }
    } else {
        block->state = BlockState::FAILED;
        block->status = ret;
    }
    block->condition.notify_all();
    return ret;
}

bool UdmfFuseController::EvictOldestBlockLocked()
{
    auto oldest = blocks_.end();
    for (auto it = blocks_.begin(); it != blocks_.end(); ++it) {
        const auto &entry = it->second;
        if (entry->state != BlockState::READY || !entry->cacheReserved || entry.use_count() != 1) {
            continue;
        }
        if (oldest == blocks_.end() || entry->lastAccess < oldest->second->lastAccess) {
            oldest = it;
        }
    }
    if (oldest == blocks_.end()) {
        return false;
    }
    cachedBytes_ -= oldest->second->data.size();
    FuseCacheBudget::GetInstance().Release(oldest->second->data.size());
    blocks_.erase(oldest);
    return true;
}

void UdmfFuseController::EvictBlocksLocked(size_t incomingBytes)
{
    while (cachedBytes_ > MAX_CONTROLLER_CACHE_BYTES || incomingBytes > MAX_CONTROLLER_CACHE_BYTES - cachedBytes_) {
        if (!EvictOldestBlockLocked()) {
            return;
        }
    }
}

void UdmfFuseController::ReleaseTransientBlock(const BlockKey &key, const std::shared_ptr<BlockEntry> &block)
{
    if (block == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (block->cacheReserved || block->state != BlockState::READY) {
        return;
    }
    auto it = blocks_.find(key);
    if (it != blocks_.end() && it->second == block && block.use_count() == 2) {
        blocks_.erase(it);
    }
}

void UdmfFuseController::RemoveBlocksLocked(const std::vector<fuse_ino_t> &inodes)
{
    std::unordered_set<fuse_ino_t> removed(inodes.begin(), inodes.end());
    for (auto it = blocks_.begin(); it != blocks_.end();) {
        if (removed.find(it->first.inode) == removed.end()) {
            ++it;
            continue;
        }
        auto &entry = it->second;
        if (entry->state == BlockState::READY && entry->cacheReserved) {
            cachedBytes_ -= entry->data.size();
            FuseCacheBudget::GetInstance().Release(entry->data.size());
        }
        entry->state = BlockState::CANCELED;
        entry->status = -ECANCELED;
        entry->condition.notify_all();
        it = blocks_.erase(it);
    }
}

void UdmfFuseController::ClearBlocksLocked()
{
    for (auto &[key, entry] : blocks_) {
        (void)key;
        if (entry->state == BlockState::READY && entry->cacheReserved) {
            FuseCacheBudget::GetInstance().Release(entry->data.size());
        }
        entry->state = BlockState::CANCELED;
        entry->status = -ECANCELED;
        entry->condition.notify_all();
    }
    blocks_.clear();
    cachedBytes_ = 0;
}

void UdmfFuseController::ProviderCancel(const sptr<IRemoteObject> &provider, const std::vector<std::string> &ids)
{
    auto virtualProvider = iface_cast<IVirtualEntryProvider>(provider);
    if (virtualProvider != nullptr && !ids.empty()) {
        (void)virtualProvider->Cancel(ids);
    }
}

void UdmfFuseController::LoopMain()
{
    struct fuse_session *session = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        session = fuseSession_;
    }
    if (session == nullptr) {
        return;
    }
    ZLOGI("Start UDMF FUSE loop, userId:%{public}d", userId_);
    struct fuse_loop_config *config = fuse_loop_cfg_create();
    if (config == nullptr) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (loopState_ != LoopState::STOPPING) {
                loopState_ = LoopState::FAILED;
                loopResult_ = -ENOMEM;
            }
        }
        loopCondition_.notify_all();
        ZLOGE("Create UDMF FUSE loop config failed, userId:%{public}d", userId_);
        return;
    }
    fuse_loop_cfg_set_idle_threads(config, 1);
    fuse_loop_cfg_set_max_threads(config, MAX_FUSE_THREADS);
    fuse_loop_cfg_set_clone_fd(config, 0);
    int32_t ret = fuse_session_loop_mt(session, config);
    fuse_loop_cfg_destroy(config);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (loopState_ != LoopState::STOPPING) {
            loopState_ = LoopState::FAILED;
            loopResult_ = ret == 0 ? -EIO : ret;
        }
    }
    loopCondition_.notify_all();
    ZLOGI("UDMF FUSE loop exited, userId:%{public}d ret:%{public}d", userId_, ret);
}

void UdmfFuseController::WakeLoop()
{
    int wakeFd = -1;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        wakeFd = wakeFd_;
    }
    if (wakeFd >= 0) {
        uint64_t value = 1;
        (void)write(wakeFd, &value, sizeof(value));
    }
}

ssize_t UdmfFuseController::ReadFuseFd(int fd, void *buf, size_t len, void *userdata)
{
    auto *controller = static_cast<UdmfFuseController *>(userdata);
    if (controller == nullptr) {
        errno = EINVAL;
        return -1;
    }
    int wakeFd = -1;
    {
        std::lock_guard<std::mutex> lock(controller->mutex_);
        wakeFd = controller->wakeFd_;
    }
    for (int32_t retry = 0; retry < FUSE_EMPTY_READ_RETRY_LIMIT; ++retry) {
        struct pollfd pollFds[FUSE_POLL_FD_COUNT] = { { fd, POLLIN, 0 }, { wakeFd, POLLIN, 0 } };
        int ret = 0;
        do {
            ret = poll(pollFds, wakeFd >= 0 ? FUSE_POLL_FD_COUNT : 1, -1);
        } while (ret < 0 && errno == EINTR);
        if (ret < 0) {
            ZLOGE("Poll FUSE fd failed, userId:%{public}d errno:%{public}d", controller->userId_, errno);
            return -1;
        }
        if (wakeFd >= 0 && (pollFds[1].revents & POLLIN) != 0) {
            errno = EINTR;
            return -1;
        }
        if ((pollFds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0 && (pollFds[0].revents & POLLIN) == 0) {
            ZLOGE("Invalid FUSE fd event, userId:%{public}d revents:%{public}d", controller->userId_,
                pollFds[0].revents);
            errno = EIO;
            return -1;
        }
        ssize_t bytesRead = read(fd, buf, len);
        if (bytesRead != 0) {
            if (bytesRead < 0 && errno != EINTR) {
                ZLOGE("Read FUSE fd failed, userId:%{public}d errno:%{public}d", controller->userId_, errno);
            }
            return bytesRead;
        }
        // A zero result makes the libfuse worker exit without terminating the
        // multithreaded coordinator. Retry transient empty reads to avoid leaving
        // the mount alive with no worker available for FUSE_INIT.
        ZLOGW("Empty FUSE fd read, userId:%{public}d retry:%{public}d", controller->userId_, retry + 1);
    }
    errno = EIO;
    return -1;
}

ssize_t UdmfFuseController::WriteFuseFd(int fd, struct iovec *iov, int count, void *userdata)
{
    auto *controller = static_cast<UdmfFuseController *>(userdata);
    ssize_t bytesWritten = writev(fd, iov, count);
    if (bytesWritten < 0 && controller != nullptr) {
        ZLOGE("Write FUSE fd failed, userId:%{public}d errno:%{public}d", controller->userId_, errno);
    }
    return bytesWritten;
}
} // namespace OHOS::UDMF
