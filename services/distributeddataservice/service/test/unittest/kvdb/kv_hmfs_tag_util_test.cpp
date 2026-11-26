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

#define LOG_TAG "KvHmfsTagUtilTest"
#include "kv_hmfs_tag_util.h"

#include <fcntl.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <string>

namespace {
constexpr unsigned long HMFS_IOCTL_MAGIC = 0xF5;
constexpr const char *TEST_BASE_DIR = "/data/local/tmp/kv_hmfs_tag_util_test";
constexpr const char *TEST_BASE_DIR_FALLBACK = "/tmp/kv_hmfs_tag_util_test";
std::string g_baseDir;

std::string BaseDir()
{
    return g_baseDir;
}

struct HmfsKeyFileArgs {
    char filename[256];
    uint32_t flags;
};

constexpr unsigned long HMFS_IOC_KEY_FILE_SETFLAGS = _IOW(HMFS_IOCTL_MAGIC, 72, HmfsKeyFileArgs);
constexpr unsigned long HMFS_IOC_KEY_FILE_GETFLAGS = _IOWR(HMFS_IOCTL_MAGIC, 73, HmfsKeyFileArgs);

using IoctlHandler = std::function<int(int, unsigned long, void *)>;
IoctlHandler g_ioctlHandler;

struct IoctlPlan {
    int getRet = 0;
    int getErr = 0;
    int setRet = 0;
    int setErr = 0;
    uint32_t getFlags = 0;
    std::string taggedName;
    int getCalls = 0;
    int setCalls = 0;
};

IoctlHandler MakeIoctlHandler(std::shared_ptr<IoctlPlan> plan)
{
    return [plan](int fd, unsigned long request, void *arg) {
        auto *args = static_cast<HmfsKeyFileArgs *>(arg);
        std::string name = (args != nullptr) ? std::string(args->filename) : std::string();
        if (request == HMFS_IOC_KEY_FILE_GETFLAGS) {
            ++plan->getCalls;
            if (plan->getRet != 0) {
                errno = plan->getErr;
                return plan->getRet;
            }
            if (args != nullptr) {
                bool tagged = !plan->taggedName.empty() && name == plan->taggedName;
                args->flags = tagged ? 1u : plan->getFlags;
            }
            return 0;
        }
        if (request == HMFS_IOC_KEY_FILE_SETFLAGS) {
            ++plan->setCalls;
            if (plan->setRet != 0) {
                errno = plan->setErr;
                return plan->setRet;
            }
            return 0;
        }
        return static_cast<int>(syscall(SYS_ioctl, fd, request, arg));
    };
}

class IoctlHookGuard {
public:
    explicit IoctlHookGuard(const IoctlHandler &handler)
    {
        g_ioctlHandler = handler;
    }

    ~IoctlHookGuard()
    {
        g_ioctlHandler = nullptr;
    }
};

bool MakeDir(const std::string &path)
{
    return mkdir(path.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0 || errno == EEXIST;
}
} // namespace

extern "C" int __wrap_ioctl(int fd, unsigned long request, void *arg) /* NOLINT */
{
    if (g_ioctlHandler != nullptr) {
        return g_ioctlHandler(fd, request, arg);
    }
    return static_cast<int>(syscall(SYS_ioctl, fd, request, arg));
}

namespace OHOS::Test {
using namespace testing::ext;
using namespace OHOS::DistributedKv;

class KvHmfsTagUtilTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp(void);
    void TearDown(void);
};

void KvHmfsTagUtilTest::SetUpTestCase(void)
{
    g_baseDir = TEST_BASE_DIR;
    if (!MakeDir(g_baseDir)) {
        g_baseDir = TEST_BASE_DIR_FALLBACK;
        if (!MakeDir(g_baseDir)) {
            g_baseDir.clear();
        }
    }
}

void KvHmfsTagUtilTest::TearDownTestCase(void)
{
}

void KvHmfsTagUtilTest::SetUp(void)
{
    ASSERT_FALSE(g_baseDir.empty());
    ASSERT_TRUE(MakeDir(g_baseDir));
}

void KvHmfsTagUtilTest::TearDown(void)
{
    (void)rmdir(g_baseDir.c_str());
}

/**
 * @tc.name: KvHmfsTagUtil_IsValidFileName_001
 * @tc.desc: Cover every branch of the file name validation helper
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvHmfsTagUtilTest, KvHmfsTagUtil_IsValidFileName_001, TestSize.Level0)
{
    EXPECT_TRUE(KvHmfsTagUtil::IsValidFileName("gen_natural_store.db"));
    EXPECT_TRUE(KvHmfsTagUtil::IsValidFileName(std::string(KvHmfsTagUtil::MAX_FILE_NAME_LEN, 'a')));
    EXPECT_FALSE(KvHmfsTagUtil::IsValidFileName(""));
    EXPECT_FALSE(KvHmfsTagUtil::IsValidFileName(std::string(KvHmfsTagUtil::MAX_FILE_NAME_LEN + 1, 'a')));
    EXPECT_FALSE(KvHmfsTagUtil::IsValidFileName("."));
    EXPECT_FALSE(KvHmfsTagUtil::IsValidFileName(".."));
    EXPECT_FALSE(KvHmfsTagUtil::IsValidFileName("dir/file.db"));
}

/**
 * @tc.name: KvHmfsTagUtil_InvalidName_001
 * @tc.desc: Cover the invalid name rejection of ExecuteIoctl and the errno conversion helper
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvHmfsTagUtilTest, KvHmfsTagUtil_InvalidName_001, TestSize.Level0)
{
    EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(-1, HMFS_IOC_KEY_FILE_GETFLAGS, "", nullptr), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(-1, HMFS_IOC_KEY_FILE_GETFLAGS, ".", nullptr), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(-1, HMFS_IOC_KEY_FILE_GETFLAGS, "..", nullptr), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(-1, HMFS_IOC_KEY_FILE_GETFLAGS, "dir/file.db", nullptr), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(
                  -1, HMFS_IOC_KEY_FILE_GETFLAGS, std::string(KvHmfsTagUtil::MAX_FILE_NAME_LEN + 1, 'a'), nullptr),
        -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::NegateErrno(0), -EIO);
    EXPECT_EQ(KvHmfsTagUtil::NegateErrno(ENOENT), -ENOENT);
}

/**
 * @tc.name: KvHmfsTagUtil_ExecuteIoctlOutFlags_001
 * @tc.desc: Cover GET and CLEAR ioctl results with and without the out flags pointer, and both ioctl failures
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvHmfsTagUtilTest, KvHmfsTagUtil_ExecuteIoctlOutFlags_001, TestSize.Level0)
{
    std::string dir = BaseDir() + "/flags_dir";
    ASSERT_TRUE(MakeDir(dir));
    int dirFd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);

    constexpr int expectedGetCalls = 3;
    constexpr int expectedSetCalls = 2;
    auto okPlan = std::make_shared<IoctlPlan>();
    okPlan->taggedName = "tagged.db";
    {
        IoctlHookGuard guard(MakeIoctlHandler(okPlan));
        uint32_t flags = 0;
        EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(dirFd, HMFS_IOC_KEY_FILE_GETFLAGS, "tagged.db", &flags), 0);
        EXPECT_EQ(flags, 1U);
        EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(dirFd, HMFS_IOC_KEY_FILE_GETFLAGS, "untagged.db", &flags), 0);
        EXPECT_EQ(flags, 0U);
        EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(dirFd, HMFS_IOC_KEY_FILE_GETFLAGS, "untagged.db", nullptr), 0);
        EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(dirFd, HMFS_IOC_KEY_FILE_SETFLAGS, "untagged.db", nullptr), 0);
        EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(dirFd, HMFS_IOC_KEY_FILE_SETFLAGS, "untagged.db", &flags), 0);
    }
    EXPECT_EQ(okPlan->getCalls, expectedGetCalls);
    EXPECT_EQ(okPlan->setCalls, expectedSetCalls);

    auto failPlan = std::make_shared<IoctlPlan>();
    failPlan->getRet = -1;
    failPlan->getErr = EACCES;
    failPlan->setRet = -1;
    failPlan->setErr = EPERM;
    {
        IoctlHookGuard guard(MakeIoctlHandler(failPlan));
        EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(dirFd, HMFS_IOC_KEY_FILE_GETFLAGS, "get.db", nullptr), -EACCES);
        EXPECT_EQ(KvHmfsTagUtil::ExecuteIoctl(dirFd, HMFS_IOC_KEY_FILE_SETFLAGS, "set.db", nullptr), -EPERM);
    }
    close(dirFd);
    (void)rmdir(dir.c_str());
}

/**
 * @tc.name: KvHmfsTagUtil_ExecuteByPathMatrix_001
 * @tc.desc: Cover every outcome of the path based wrapper: empty, missing separator, root separated, trailing
 *           separator, open failure and successful open for GET, SET and CLEAR
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvHmfsTagUtilTest, KvHmfsTagUtil_ExecuteByPathMatrix_001, TestSize.Level0)
{
    std::string baseDir = BaseDir();
    auto plan = std::make_shared<IoctlPlan>();
    plan->taggedName = "tagged.db";
    IoctlHookGuard guard(MakeIoctlHandler(plan));
    uint32_t flags = 0;
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_GETFLAGS, "", &flags), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_GETFLAGS, "plainname", &flags), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_GETFLAGS, "/plainfile.db", &flags), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_GETFLAGS, baseDir + "/", &flags), -EINVAL);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_GETFLAGS, baseDir + "/no_dir/file.db", &flags), -ENOENT);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_GETFLAGS, baseDir + "/tagged.db", &flags), 0);
    EXPECT_EQ(flags, 1U);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_SETFLAGS, baseDir + "/set.db", nullptr), 0);
    EXPECT_EQ(KvHmfsTagUtil::ExecuteByPath(HMFS_IOC_KEY_FILE_SETFLAGS, baseDir + "/set.db", &flags), 0);
}

/**
 * @tc.name: KvHmfsTagUtil_GetFileFlagMatrix_001
 * @tc.desc: Cover the fd and path based GET/CLEAR helpers for tagged, untagged and ioctl failure results
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvHmfsTagUtilTest, KvHmfsTagUtil_GetFileFlagMatrix_001, TestSize.Level0)
{
    std::string dir = BaseDir() + "/flag_matrix_dir";
    ASSERT_TRUE(MakeDir(dir));
    int dirFd = open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    ASSERT_GE(dirFd, 0);
    std::string path = dir + "/tagged.db";

    auto okPlan = std::make_shared<IoctlPlan>();
    okPlan->taggedName = "tagged.db";
    {
        IoctlHookGuard guard(MakeIoctlHandler(okPlan));
        EXPECT_EQ(KvHmfsTagUtil::GetKeyFileFlag(dirFd, "tagged.db"), KvHmfsTagUtil::FLAG_SET);
        EXPECT_EQ(KvHmfsTagUtil::GetKeyFileFlag(dirFd, "untagged.db"), KvHmfsTagUtil::FLAG_UNSET);
        EXPECT_EQ(KvHmfsTagUtil::SetKeyFileFlag(dirFd, "set.db"), 0);
        EXPECT_EQ(KvHmfsTagUtil::GetKeyFileFlag(path), KvHmfsTagUtil::FLAG_SET);
        EXPECT_EQ(KvHmfsTagUtil::GetKeyFileFlag(dir + "/untagged.db"), KvHmfsTagUtil::FLAG_UNSET);
        EXPECT_EQ(KvHmfsTagUtil::SetKeyFileFlag(dir + "/set.db"), 0);
    }

    auto failPlan = std::make_shared<IoctlPlan>();
    failPlan->getRet = -1;
    failPlan->getErr = EACCES;
    failPlan->setRet = -1;
    failPlan->setErr = EACCES;
    {
        IoctlHookGuard guard(MakeIoctlHandler(failPlan));
        EXPECT_EQ(KvHmfsTagUtil::GetKeyFileFlag(dirFd, "get.db"), -EACCES);
        EXPECT_EQ(KvHmfsTagUtil::SetKeyFileFlag(dirFd, "set.db"), -EACCES);
        EXPECT_EQ(KvHmfsTagUtil::GetKeyFileFlag(path), -EACCES);
        EXPECT_EQ(KvHmfsTagUtil::SetKeyFileFlag(path), -EACCES);
    }
    close(dirFd);
    (void)rmdir(dir.c_str());
}

/**
 * @tc.name: KvHmfsTagUtil_ValidPath_DoesNotBreakFile_001
 * @tc.desc: The helper degrades silently and keeps the target file on a normal file system
 * @tc.type: FUNC
 * @tc.author: agent
 */
HWTEST_F(KvHmfsTagUtilTest, KvHmfsTagUtil_ValidPath_DoesNotBreakFile_001, TestSize.Level0)
{
    std::string path = BaseDir() + "/kv_hmfs_tag_util_test.db";
    int fd = open(path.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    ASSERT_GE(fd, 0);
    close(fd);
    (void)KvHmfsTagUtil::SetKeyFileFlag(path);
    (void)KvHmfsTagUtil::GetKeyFileFlag(path);
    EXPECT_EQ(access(path.c_str(), F_OK), 0);
    (void)remove(path.c_str());
}
} // namespace OHOS::Test
