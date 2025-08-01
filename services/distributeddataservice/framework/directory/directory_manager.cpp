/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#define LOG_TAG "DirectoryManager"
#include "directory/directory_manager.h"

#include <dirent.h>
#include <string>
#include <sys/stat.h>

#include "accesstoken_kit.h"
#include "log_print.h"
#include "types.h"
#include "unistd.h"
namespace OHOS::DistributedData {
using OHOS::DistributedKv::SecurityLevel;
using namespace OHOS::Security::AccessToken;
DirectoryManager::DirectoryManager()
    : actions_({ { "{security}", &DirectoryManager::GetSecurity }, { "{store}", &DirectoryManager::GetStore },
        { "{type}", &DirectoryManager::GetType }, { "{area}", &DirectoryManager::GetArea },
        { "{userId}", &DirectoryManager::GetUserId }, { "{bundleName}", &DirectoryManager::GetBundleName },
        { "{hapName}", &DirectoryManager::GetHapName }, { "{customDir}", &DirectoryManager::GetCustomDir } })
{
}

DirectoryManager &DirectoryManager::GetInstance()
{
    static DirectoryManager instance;
    return instance;
}

std::string DirectoryManager::GetStorePath(const StoreMetaData &metaData, uint32_t version)
{
    return GenPath(metaData, version, "");
}

std::string DirectoryManager::GetStoreBackupPath(const StoreMetaData &metaData, uint32_t version)
{
    auto rootBackupPath = GenPath(metaData, version, "backup");
    return rootBackupPath + "/" + metaData.storeId;
}

std::string DirectoryManager::GetSecretKeyPath(const StoreMetaData &metaData, uint32_t version)
{
    return GenPath(metaData, version, "secret");
}

std::string DirectoryManager::GetMetaStorePath(uint32_t version)
{
    int32_t index = GetVersionIndex(version);
    if (index < 0) {
        return "";
    }

    auto &strategy = strategies_[index];
    if (strategy.autoCreate) {
        CreateDirectory(strategy.metaPath);
    }
    return strategy.metaPath;
}

std::string DirectoryManager::GetMetaBackupPath(uint32_t version)
{
    int32_t index = GetVersionIndex(version);
    if (index < 0) {
        return "";
    }

    auto &strategy = strategies_[index];
    std::string path = strategy.metaPath + "/backup";
    if (strategy.autoCreate) {
        CreateDirectory(path);
    }
    return path;
}

std::string DirectoryManager::GetClonePath(const std::string &userId, uint32_t version)
{
    int32_t index = GetVersionIndex(version);
    if (index < 0) {
        return "";
    }

    auto &strategy = strategies_[index];
    auto path = strategy.clonePath;
    std::string pattern = "{userId}";
    size_t pos = path.find(pattern);
    if (pos != std::string::npos) {
        path.replace(pos, pattern.length(), userId);
        if (CreateDirectory(path.substr(0, path.rfind('/')))) {
            return path;
        } else {
            return "";
        };
    }
    return "";
}

void DirectoryManager::Initialize(const std::vector<Strategy> &strategies, const std::vector<StoreType> &storeTypes)
{
    strategies_.resize(strategies.size());
    for (size_t i = 0; i < strategies.size(); ++i) {
        const Strategy &strategy = strategies[i];
        StrategyImpl &impl = strategies_[i];
        impl.autoCreate = strategy.autoCreate;
        impl.version = strategy.version;
        impl.metaPath = strategy.metaPath;
        impl.path = Split(strategy.pattern, "/");
        impl.clonePath = strategy.clonePath;
        impl.pipes.clear();
        for (auto &value : impl.path) {
            auto it = actions_.find(value);
            impl.pipes.push_back(it == actions_.end() ? nullptr : it->second);
        }
    }

    std::sort(strategies_.begin(), strategies_.end(),
        [](const StrategyImpl &curr, const StrategyImpl &prev) { return curr.version > prev.version; });

    storeTypes_ = storeTypes;
}

std::string DirectoryManager::GetType(const StoreMetaData &metaData) const
{
    auto type = AccessTokenKit::GetTokenTypeFlag(metaData.tokenId);
    if (type == TOKEN_NATIVE || type == TOKEN_SHELL) {
        return "service";
    }
    return "app";
}

std::string DirectoryManager::GetStore(const StoreMetaData &metaData) const
{
    for (const auto &storeType : storeTypes_) {
        if (metaData.storeType >= storeType.range.front() && metaData.storeType <= storeType.range.back()) {
            return storeType.type;
        }
    }
    return "other";
}

std::string DirectoryManager::GetSecurity(const StoreMetaData &metaData) const
{
    switch (metaData.securityLevel) {
        case SecurityLevel::NO_LABEL:
            if ((metaData.bundleName != metaData.appId) || (metaData.appType != "harmony")) {
                break;
            }
            [[fallthrough]];
        case SecurityLevel::S0:
            [[fallthrough]];
        case SecurityLevel::S1:
            return "misc_de";
    }
    return "misc_ce";
}

std::string DirectoryManager::GetArea(const StoreMetaData &metaData) const
{
    return std::string("el") + std::to_string(metaData.area);
}

std::string DirectoryManager::GetUserId(const StoreMetaData &metaData) const
{
    auto type = AccessTokenKit::GetTokenTypeFlag(metaData.tokenId);
    if ((type == TOKEN_NATIVE || type == TOKEN_SHELL) && (metaData.user == StoreMetaData::ROOT_USER)) {
        return "public";
    }
    return metaData.user;
}

std::string DirectoryManager::GetBundleName(const StoreMetaData &metaData) const
{
    if (metaData.instanceId == 0) {
        return metaData.bundleName;
    }
    return "+clone-" + std::to_string(metaData.instanceId) + "+" + metaData.bundleName;
}

std::string DirectoryManager::GetHapName(const StoreMetaData &metaData) const
{
    return metaData.hapName;
}

std::string DirectoryManager::GetCustomDir(const StoreMetaData &metaData) const
{
    return metaData.customDir;
}

std::vector<std::string> DirectoryManager::Split(const std::string &source, const std::string &pattern) const
{
    std::vector<std::string> values;
    std::string::size_type pos = 0;
    std::string::size_type nextPos = 0;
    while (nextPos != std::string::npos) {
        nextPos = source.find(pattern, pos);
        if (nextPos == pos) {
            pos = pos + pattern.size();
            continue;
        }
        values.push_back(source.substr(pos, nextPos - pos));
        pos = nextPos + pattern.size();
    }
    return values;
}

int32_t DirectoryManager::GetVersionIndex(uint32_t version) const
{
    for (size_t i = 0; i < strategies_.size(); ++i) {
        if (version >= strategies_[i].version) {
            return i;
        }
    }
    return int32_t(strategies_.size()) - 1;
}

std::vector<uint32_t> DirectoryManager::GetVersions()
{
    std::vector<uint32_t> versions;
    for (size_t i = 0; i < strategies_.size(); ++i) {
        versions.push_back(strategies_[i].version);
    }
    return versions;
}

std::string DirectoryManager::GenPath(const StoreMetaData &metaData, uint32_t version, const std::string &exPath) const
{
    int32_t index = GetVersionIndex(version);
    if (index < 0) {
        return "";
    }
    std::string path;
    auto &strategy = strategies_[index];
    for (size_t i = 0; i < strategy.pipes.size(); ++i) {
        std::string section;
        if (strategy.pipes[i] == nullptr) {
            section = strategy.path[i];
        } else {
            section = (this->*(strategy.pipes[i]))(metaData);
        }
        if (section.empty()) {
            continue;
        }
        path += "/" + section;
    }
    if (!exPath.empty()) {
        path += "/" + exPath;
    }
    if (strategy.autoCreate) {
        CreateDirectory(path);
    }
    return path;
}

bool DirectoryManager::CreateDirectory(const std::string &path) const
{
    if (access(path.c_str(), F_OK) == 0) {
        return true;
    }

    std::string::size_type index = 0;
    do {
        std::string subPath;
        index = path.find('/', index + 1);
        if (index == std::string::npos) {
            subPath = path;
        } else {
            subPath = path.substr(0, index);
        }

        if (access(subPath.c_str(), F_OK) != 0) {
            if (mkdir(subPath.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) != 0) {
                ZLOGE("mkdir error:%{public}d", errno);
                return false;
            }
        }
    } while (index != std::string::npos);

    return access(path.c_str(), F_OK) == 0;
}

bool DirectoryManager::DeleteDirectory(const char* path)
{
    if (path == nullptr) {
        return false;
    }
    DIR* dir;
    struct dirent* dirEntry;
    struct stat buf;
    char* curWorkDir = getcwd(nullptr, 0);
    if ((dir = opendir(path)) == nullptr) {
        return true;
    }
    if (chdir(path) == -1) {
        closedir(dir);
        return false;
    }
    while ((dirEntry = readdir(dir))) {
        if ((strcmp(dirEntry->d_name, ".") == 0) || (strcmp(dirEntry->d_name, "..") == 0)) {
            continue;
        }
        if (stat(dirEntry->d_name, &buf) == -1) {
            closedir(dir);
            return false;
        }
        if (S_ISDIR(buf.st_mode)) {
            DeleteDirectory(dirEntry->d_name);
            continue;
        }
        if (remove(dirEntry->d_name) == -1) {
            closedir(dir);
            return false;
        }
    }
    closedir(dir);
    if (chdir(curWorkDir) == -1 || rmdir(path) == -1) {
        return false;
    }
    return true;
}
} // namespace OHOS::DistributedData
