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

#include "udmf_fuse_lowlevel_mock.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <unistd.h>

namespace OHOS::UDMF {
namespace {
constexpr uint32_t FUSE_PROTOCOL_MAJOR = 7;
constexpr uint32_t FUSE_PROTOCOL_MINOR = 38;
}

std::atomic<FuseLowlevelMock *> FuseLowlevelMock::instance_{ nullptr };

FuseLowlevelMock::FuseLowlevelMock()
{
    instance_.store(this);
}

FuseLowlevelMock::~FuseLowlevelMock()
{
    instance_.store(nullptr);
}

FuseLowlevelMock *FuseLowlevelMock::Get()
{
    return instance_.load();
}

FuseLowlevelMock::Request &FuseLowlevelMock::GetRequest(fuse_req_t req)
{
    return *reinterpret_cast<Request *>(req);
}

FuseLowlevelMock::Request FuseLowlevelMock::MakeRequest(uid_t uid) const
{
    Request request;
    request.userdata = userdata;
    request.context.uid = uid;
    request.context.gid = uid;
    return request;
}

struct fuse_session *FuseLowlevelMock::CreateSession(const struct fuse_lowlevel_ops *callbacks, void *value)
{
    if (failSession) {
        return nullptr;
    }
    operations = *callbacks;
    userdata = value;
    auto *session = new Session();
    session->userdata = value;
    ++created;
    return reinterpret_cast<struct fuse_session *>(session);
}

int FuseLowlevelMock::RunLoop(struct fuse_session *value)
{
    if (loopStatus != 0) {
        return loopStatus;
    }
    auto *session = reinterpret_cast<Session *>(value);
    if (initialize) {
        struct fuse_conn_info connection {};
        connection.proto_major = FUSE_PROTOCOL_MAJOR;
        connection.proto_minor = FUSE_PROTOCOL_MINOR;
        connection.want = FUSE_CAP_READDIRPLUS;
        operations.init(session->userdata, &connection);
    }
    std::unique_lock<std::mutex> lock(session->mutex);
    session->condition.wait(lock, [session] { return session->exited; });
    return 0;
}

size_t FuseLowlevelMock::AddEntry(fuse_req_t req, char *buffer, size_t capacity, const char *name)
{
    size_t length = std::strlen(name) + 1;
    if (buffer != nullptr && capacity >= length) {
        GetRequest(req).names.emplace_back(name);
        std::copy_n(name, length, buffer);
    }
    return length;
}
} // namespace OHOS::UDMF

using OHOS::UDMF::FuseLowlevelMock;

extern "C" {
struct fuse_session *FuseSessionNewVersioned(struct fuse_args *args, const struct fuse_lowlevel_ops *operations,
    size_t size, struct libfuse_version *version, void *userdata) __asm__("fuse_session_new_versioned");
struct fuse_session *FuseSessionNewVersioned(struct fuse_args *args, const struct fuse_lowlevel_ops *operations,
    size_t size, struct libfuse_version *version, void *userdata)
{
    (void)args;
    (void)size;
    (void)version;
    auto *mock = FuseLowlevelMock::Get();
    return mock == nullptr ? nullptr : mock->CreateSession(operations, userdata);
}

int FuseSessionCustomIo317(struct fuse_session *value, const struct fuse_custom_io *io, size_t size, int fd)
    __asm__("fuse_session_custom_io_317");
int FuseSessionCustomIo317(struct fuse_session *value, const struct fuse_custom_io *io, size_t size, int fd)
{
    (void)size;
    auto *mock = FuseLowlevelMock::Get();
    if (mock->customIoStatus != 0) {
        return mock->customIoStatus;
    }
    mock->customIo = *io;
    reinterpret_cast<FuseLowlevelMock::Session *>(value)->fd = fd;
    return 0;
}

void FuseSessionExit(struct fuse_session *value) __asm__("fuse_session_exit");
void FuseSessionExit(struct fuse_session *value)
{
    auto *session = reinterpret_cast<FuseLowlevelMock::Session *>(value);
    {
        std::lock_guard<std::mutex> lock(session->mutex);
        session->exited = true;
    }
    session->condition.notify_all();
}

void FuseSessionDestroy(struct fuse_session *value) __asm__("fuse_session_destroy");
void FuseSessionDestroy(struct fuse_session *value)
{
    auto *session = reinterpret_cast<FuseLowlevelMock::Session *>(value);
    if (session->fd >= 0) {
        (void)close(session->fd);
    }
    delete session;
    ++FuseLowlevelMock::Get()->destroyed;
}

int FuseSessionLoopMt(struct fuse_session *session, struct fuse_loop_config *config) __asm__("fuse_session_loop_mt");
int FuseSessionLoopMt(struct fuse_session *session, struct fuse_loop_config *config)
{
    (void)config;
    return FuseLowlevelMock::Get()->RunLoop(session);
}

struct fuse_loop_config *FuseLoopCfgCreate() __asm__("fuse_loop_cfg_create");
struct fuse_loop_config *FuseLoopCfgCreate()
{
    return FuseLowlevelMock::Get()->failLoopConfig
        ? nullptr : reinterpret_cast<struct fuse_loop_config *>(new uint32_t(0));
}

void FuseLoopCfgDestroy(struct fuse_loop_config *config) __asm__("fuse_loop_cfg_destroy");
void FuseLoopCfgDestroy(struct fuse_loop_config *config)
{
    delete reinterpret_cast<uint32_t *>(config);
}

void FuseLoopCfgSetIdleThreads(struct fuse_loop_config *config, unsigned int value)
    __asm__("fuse_loop_cfg_set_idle_threads");
void FuseLoopCfgSetIdleThreads(struct fuse_loop_config *config, unsigned int value)
{
    (void)config;
    (void)value;
}

void FuseLoopCfgSetMaxThreads(struct fuse_loop_config *config, unsigned int value)
    __asm__("fuse_loop_cfg_set_max_threads");
void FuseLoopCfgSetMaxThreads(struct fuse_loop_config *config, unsigned int value)
{
    (void)config;
    FuseLowlevelMock::Get()->maxThreads = value;
}

void FuseLoopCfgSetCloneFd(struct fuse_loop_config *config, unsigned int value) __asm__("fuse_loop_cfg_set_clone_fd");
void FuseLoopCfgSetCloneFd(struct fuse_loop_config *config, unsigned int value)
{
    (void)config;
    (void)value;
}

void *fuse_req_userdata(fuse_req_t req)
{
    return FuseLowlevelMock::GetRequest(req).userdata;
}

const struct fuse_ctx *fuse_req_ctx(fuse_req_t req)
{
    auto &request = FuseLowlevelMock::GetRequest(req);
    return request.contextAvailable ? &request.context : nullptr;
}

int fuse_reply_err(fuse_req_t req, int error)
{
    auto &request = FuseLowlevelMock::GetRequest(req);
    request.error = error;
    ++request.replies;
    return 0;
}

void fuse_reply_none(fuse_req_t req)
{
    auto &request = FuseLowlevelMock::GetRequest(req);
    request.error = 0;
    ++request.replies;
}

int fuse_reply_entry(fuse_req_t req, const struct fuse_entry_param *entry)
{
    FuseLowlevelMock::GetRequest(req).entry = *entry;
    return fuse_reply_err(req, 0);
}

int fuse_reply_attr(fuse_req_t req, const struct stat *attr, double timeout)
{
    (void)timeout;
    FuseLowlevelMock::GetRequest(req).attr = *attr;
    return fuse_reply_err(req, 0);
}

int fuse_reply_open(fuse_req_t req, const struct fuse_file_info *info)
{
    FuseLowlevelMock::GetRequest(req).fileInfo = *info;
    return fuse_reply_err(req, 0);
}

int fuse_reply_buf(fuse_req_t req, const char *buffer, size_t size)
{
    auto &request = FuseLowlevelMock::GetRequest(req);
    request.bytes.clear();
    if (size != 0) {
        request.bytes.assign(buffer, buffer + size);
    }
    return fuse_reply_err(req, 0);
}

int fuse_reply_statfs(fuse_req_t req, const struct statvfs *stat)
{
    FuseLowlevelMock::GetRequest(req).statFs = *stat;
    return fuse_reply_err(req, 0);
}

int fuse_reply_lseek(fuse_req_t req, off_t offset)
{
    FuseLowlevelMock::GetRequest(req).seekOffset = offset;
    return fuse_reply_err(req, 0);
}

size_t fuse_add_direntry(fuse_req_t req, char *buffer, size_t capacity, const char *name,
    const struct stat *attr, off_t offset)
{
    (void)attr;
    (void)offset;
    return FuseLowlevelMock::AddEntry(req, buffer, capacity, name);
}

size_t fuse_add_direntry_plus(fuse_req_t req, char *buffer, size_t capacity, const char *name,
    const struct fuse_entry_param *entry, off_t offset)
{
    (void)entry;
    (void)offset;
    return FuseLowlevelMock::AddEntry(req, buffer, capacity, name);
}
}
