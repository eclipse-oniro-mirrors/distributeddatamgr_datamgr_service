/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "cloud/cloud_server.h"
namespace OHOS::DistributedData {
CloudServer *CloudServer::instance_ = nullptr;
CloudServer *CloudServer::GetInstance()
{
    return instance_;
}

bool CloudServer::RegisterCloudInstance(CloudServer *instance)
{
    if (instance_ != nullptr) {
        return false;
    }
    instance_ = instance;
    return true;
}

std::pair<int32_t, CloudInfo> CloudServer::GetServerInfo(int32_t userId, bool needSpaceInfo)
{
    return { 0, CloudInfo() };
}

std::pair<int32_t, SchemaMeta> CloudServer::GetAppSchema(int32_t userId, const std::string &bundleName)
{
    return { 0, SchemaMeta() };
}

int32_t CloudServer::Subscribe(int32_t userId, const std::map<std::string, std::vector<Database>> &dbs)
{
    return 0;
}

int32_t CloudServer::Unsubscribe(int32_t userId, const std::map<std::string, std::vector<Database>> &dbs)
{
    return 0;
}

std::shared_ptr<AssetLoader> CloudServer::ConnectAssetLoader(uint32_t tokenId, const CloudServer::Database &dbMeta)
{
    return nullptr;
}

std::shared_ptr<AssetLoader> CloudServer::ConnectAssetLoader(
    const std::string &bundleName, int user, const CloudServer::Database &dbMeta)
{
    return nullptr;
}

std::shared_ptr<CloudDB> CloudServer::ConnectCloudDB(uint32_t tokenId, const CloudServer::Database &dbMeta)
{
    return nullptr;
}

std::shared_ptr<CloudDB> CloudServer::ConnectCloudDB(
    const std::string &bundleName, int user, const CloudServer::Database &dbMeta)
{
    return nullptr;
}

std::shared_ptr<SharingCenter> CloudServer::ConnectSharingCenter(int32_t userId, const std::string &bunleName)
{
    return nullptr;
}

void CloudServer::Clean(int32_t userId) {}

void CloudServer::ReleaseUserInfo(int32_t userId) {}

void CloudServer::Bind(std::shared_ptr<ExecutorPool> executor) {}

bool CloudServer::IsSupportCloud(int32_t userId)
{
    return false;
}

bool CloudServer::CloudDriverUpdated(const std::string &bundleName)
{
    return false;
}
} // namespace OHOS::DistributedData