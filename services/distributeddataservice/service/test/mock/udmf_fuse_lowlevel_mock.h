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

#ifndef UDMF_FUSE_LOWLEVEL_MOCK_H
#define UDMF_FUSE_LOWLEVEL_MOCK_H

#ifndef FUSE_USE_VERSION
#define FUSE_USE_VERSION 317
#endif

#include <fuse_lowlevel.h>

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace OHOS::UDMF {
class FuseLowlevelMock final {
public:
    struct Session {
        void *userdata = nullptr;
        int fd = -1;
        bool exited = false;
        std::mutex mutex;
        std::condition_variable condition;
    };

    struct Request {
        fuse_req_t Handle()
        {
            return reinterpret_cast<fuse_req_t>(this);
        }

        void *userdata = nullptr;
        struct fuse_ctx context {};
        bool contextAvailable = true;
        int error = -1;
        uint32_t replies = 0;
        struct fuse_entry_param entry {};
        struct stat attr {};
        struct statvfs statFs {};
        struct fuse_file_info fileInfo {};
        off_t seekOffset = -1;
        std::vector<uint8_t> bytes;
        std::vector<std::string> names;
    };

    FuseLowlevelMock();
    ~FuseLowlevelMock();
    static FuseLowlevelMock *Get();
    static Request &GetRequest(fuse_req_t req);
    Request MakeRequest(uid_t uid) const;
    struct fuse_session *CreateSession(const struct fuse_lowlevel_ops *operations, void *userdata);
    int RunLoop(struct fuse_session *session);
    static size_t AddEntry(fuse_req_t req, char *buffer, size_t capacity, const char *name);

    struct fuse_lowlevel_ops operations {};
    struct fuse_custom_io customIo {};
    void *userdata = nullptr;
    bool failSession = false;
    bool failLoopConfig = false;
    bool initialize = true;
    int customIoStatus = 0;
    int loopStatus = 0;
    unsigned int maxThreads = 0;
    std::atomic<uint32_t> created{ 0 };
    std::atomic<uint32_t> destroyed{ 0 };

private:
    static std::atomic<FuseLowlevelMock *> instance_;
};
} // namespace OHOS::UDMF
#endif // UDMF_FUSE_LOWLEVEL_MOCK_H
