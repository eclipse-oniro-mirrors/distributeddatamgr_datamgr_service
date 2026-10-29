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

#ifndef UDMF_FUSE_CONTROLLER_H
#define UDMF_FUSE_CONTROLLER_H

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 317
#endif

#include <fuse_lowlevel.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "iremote_object.h"
#include "virtual_entry.h"

namespace OHOS::UDMF {
class UdmfFuseController final {
public:
    struct SessionOptions {
        std::string sessionId;
        std::string alias;
        VirtualEntry root;
        sptr<IRemoteObject> provider;
        uid_t targetUid = 0;
        gid_t targetGid = 0;
    };

    explicit UdmfFuseController(int32_t userId);
    ~UdmfFuseController();

    int32_t Start(int fuseFd);
    void Stop();
    int32_t AddSession(const SessionOptions &options, std::string &relativePath);
    void RemoveSession(const std::string &sessionId);

private:
    enum class LoopState {
        IDLE,
        STARTING,
        INITIALIZED,
        STOPPING,
        FAILED,
    };

    struct Node {
        fuse_ino_t inode = 0;
        fuse_ino_t parent = 0;
        std::string sessionId;
        VirtualEntry entry;
        uid_t targetUid = 0;
        gid_t targetGid = 0;
        bool synthetic = false;
        bool statAttempted = false;
        std::vector<fuse_ino_t> children;
        std::unordered_map<std::string, fuse_ino_t> childrenByName;
    };

    struct Session {
        std::string sessionId;
        std::string alias;
        sptr<IRemoteObject> provider;
        uid_t targetUid = 0;
        gid_t targetGid = 0;
        std::vector<fuse_ino_t> nodes;
        std::vector<std::string> fileIds;
    };

    enum class BlockState {
        LOADING,
        READY,
        FAILED,
        CANCELED,
    };

    struct BlockKey {
        fuse_ino_t inode = 0;
        uint64_t index = 0;

        bool operator==(const BlockKey &other) const
        {
            return inode == other.inode && index == other.index;
        }
    };

    struct BlockKeyHash {
        size_t operator()(const BlockKey &key) const
        {
            size_t inodeHash = std::hash<fuse_ino_t>{}(key.inode);
            size_t indexHash = std::hash<uint64_t>{}(key.index);
            return inodeHash ^ (indexHash << 1);
        }
    };

    struct BlockEntry {
        BlockState state = BlockState::LOADING;
        int32_t status = 0;
        uint64_t lastAccess = 0;
        bool cacheReserved = false;
        std::chrono::steady_clock::time_point deadline;
        std::vector<uint8_t> data;
        std::condition_variable condition;
    };

    struct ProviderGate;
    class ProviderReadCallback;

    static void Init(void *userdata, struct fuse_conn_info *connection);
    static void Lookup(fuse_req_t req, fuse_ino_t parent, const char *name);
    static void Forget(fuse_req_t req, fuse_ino_t inode, uint64_t nlookup);
    static void GetAttr(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo);
    static void Access(fuse_req_t req, fuse_ino_t inode, int mask);
    static void StatFs(fuse_req_t req, fuse_ino_t inode);
    static void OpenDir(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo);
    static void ReadDir(fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, struct fuse_file_info *fileInfo);
    static void ReadDirPlus(
        fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, struct fuse_file_info *fileInfo);
    static void ReleaseDir(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo);
    static void Open(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo);
    static void Read(fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, struct fuse_file_info *fileInfo);
    static void Flush(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo);
    static void Fsync(fuse_req_t req, fuse_ino_t inode, int dataSync, struct fuse_file_info *fileInfo);
    static void Lseek(fuse_req_t req, fuse_ino_t inode, off_t offset, int whence, struct fuse_file_info *fileInfo);
    static void Release(fuse_req_t req, fuse_ino_t inode, struct fuse_file_info *fileInfo);
    static ssize_t ReadFuseFd(int fd, void *buf, size_t len, void *userdata);
    static ssize_t WriteFuseFd(int fd, struct iovec *iov, int count, void *userdata);

    int32_t CreateFuseSession(int fuseFd, struct fuse_session *&session);
    int32_t InitializeSession(struct fuse_session *session, int wakeFd);
    bool IsAllowed(fuse_req_t req, const Node &node) const;
    bool IsUidAllowed(uid_t callingUid, const Node &node) const;
    int32_t CheckAccess(uid_t callingUid, const Node &node, int mask) const;
    static int32_t GetSeekResult(const Node &node, off_t offset, int whence, off_t &result);
    void FillStatFs(uid_t callingUid, struct statvfs &stat) const;
    bool GetNode(fuse_ino_t inode, Node &node, sptr<IRemoteObject> &provider) const;
    void FillAttr(const Node &node, struct stat &attr) const;
    static void ReadDirectory(fuse_req_t req, fuse_ino_t inode, size_t size, off_t offset, bool plus);
    std::vector<Node> GetDirectoryEntries(fuse_req_t req, const Node &directory);
    int32_t RefreshFileSize(Node &node, const sptr<IRemoteObject> &provider);
    int32_t ReadFileData(const Node &node, const sptr<IRemoteObject> &provider, size_t size, off_t offset,
        std::vector<uint8_t> &result);
    int32_t AddTreeLocked(fuse_ino_t parent, const VirtualEntry &entry, Session &session, fuse_ino_t &inode);
    void RemoveNodeLocked(fuse_ino_t inode);
    static int32_t ProviderStat(const sptr<IRemoteObject> &provider, const std::string &id, VirtualEntry &entry);
    int32_t ProviderRead(const sptr<IRemoteObject> &provider, const std::string &sessionId, const std::string &id,
        int64_t offset, int32_t length, const std::chrono::steady_clock::time_point &deadline,
        std::vector<uint8_t> &bytes);
    static void ProviderCancel(const sptr<IRemoteObject> &provider, const std::vector<std::string> &ids);
    int32_t GetOrLoadBlock(const Node &node, const sptr<IRemoteObject> &provider, uint64_t blockIndex,
        std::shared_ptr<BlockEntry> &block);
    int32_t PrepareBlock(const BlockKey &key, std::shared_ptr<BlockEntry> &block, bool &shouldLoad);
    int32_t ReadBlockData(const Node &node, const sptr<IRemoteObject> &provider, uint64_t blockOffset,
        const std::shared_ptr<BlockEntry> &block, std::vector<uint8_t> &bytes);
    int32_t ReadBlockPart(const Node &node, const sptr<IRemoteObject> &provider,
        const std::shared_ptr<BlockEntry> &block, uint64_t offset, int32_t length, std::vector<uint8_t> &part);
    int32_t FinishBlockLoad(const BlockKey &key, const std::shared_ptr<BlockEntry> &block,
        std::vector<uint8_t> &bytes, int32_t status);
    bool EvictOldestBlockLocked();
    void EvictBlocksLocked(size_t incomingBytes);
    void ReleaseTransientBlock(const BlockKey &key, const std::shared_ptr<BlockEntry> &block);
    void RemoveBlocksLocked(const std::vector<fuse_ino_t> &inodes);
    void ClearBlocksLocked();
    void LoopMain();
    void WakeLoop();

    int32_t userId_ = -1;
    mutable std::mutex mutex_;
    std::unordered_map<fuse_ino_t, Node> nodes_;
    std::unordered_map<std::string, Session> sessions_;
    std::unordered_map<BlockKey, std::shared_ptr<BlockEntry>, BlockKeyHash> blocks_;
    size_t cachedBytes_ = 0;
    uint64_t accessSequence_ = 0;
    std::shared_ptr<ProviderGate> providerGate_;
    std::atomic<uint64_t> nextInode_{ FUSE_ROOT_ID + 1 };
    struct fuse_session *fuseSession_ = nullptr;
    int wakeFd_ = -1;
    std::thread loopThread_;
    std::condition_variable loopCondition_;
    LoopState loopState_ = LoopState::IDLE;
    int32_t loopResult_ = 0;
};
} // namespace OHOS::UDMF

#endif // UDMF_FUSE_CONTROLLER_H
