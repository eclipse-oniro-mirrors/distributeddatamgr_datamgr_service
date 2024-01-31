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

#define LOG_TAG "CloudServiceImpl"

#include "cloud_service_impl.h"

#include "accesstoken_kit.h"
#include "account/account_delegate.h"
#include "checker/checker_manager.h"
#include "cloud/cloud_server.h"
#include "cloud/cloud_share_event.h"
#include "cloud/make_query_event.h"
#include "cloud_value_util.h"
#include "communicator/device_manager_adapter.h"
#include "eventcenter/event_center.h"
#include "hap_token_info.h"
#include "ipc_skeleton.h"
#include "log_print.h"
#include "metadata/meta_data_manager.h"
#include "rdb_cloud_data_translate.h"
#include "rdb_types.h"
#include "runtime_config.h"
#include "store/auto_cache.h"
#include "store/general_store.h"
#include "sync_manager.h"
#include "utils/anonymous.h"
#include "values_bucket.h"
namespace OHOS::CloudData {
using namespace DistributedData;
using namespace DistributedKv;
using namespace std::chrono;
using namespace SharingUtil;
using namespace Security::AccessToken;
using DmAdapter = OHOS::DistributedData::DeviceManagerAdapter;
using Account = OHOS::DistributedKv::AccountDelegate;
using AccessTokenKit = Security::AccessToken::AccessTokenKit;
__attribute__((used)) CloudServiceImpl::Factory CloudServiceImpl::factory_;

CloudServiceImpl::Factory::Factory() noexcept
{
    FeatureSystem::GetInstance().RegisterCreator(
        CloudServiceImpl::SERVICE_NAME,
        [this]() {
            if (product_ == nullptr) {
                product_ = std::make_shared<CloudServiceImpl>();
            }
            return product_;
        },
        FeatureSystem::BIND_NOW);
    staticActs_ = std::make_shared<CloudStatic>();
    FeatureSystem::GetInstance().RegisterStaticActs(CloudServiceImpl::SERVICE_NAME, staticActs_);
}

CloudServiceImpl::Factory::~Factory() {}

CloudServiceImpl::CloudServiceImpl()
{
    EventCenter::GetInstance().Subscribe(CloudEvent::GET_SCHEMA, [this](const Event &event) {
        GetSchema(event);
    });
    EventCenter::GetInstance().Subscribe(CloudEvent::CLOUD_SHARE, [this](const Event &event) {
        CloudShare(event);
    });
    MetaDataManager::GetInstance().Subscribe(
        Subscription::GetPrefix({ "" }), [this](const std::string &key,
            const std::string &value, int32_t flag) -> auto {
            if (flag != MetaDataManager::INSERT && flag != MetaDataManager::UPDATE) {
                return true;
            }
            Subscription sub;
            Subscription::Unmarshall(value, sub);
            InitSubTask(sub);
            return true;
        }, true);
}

int32_t CloudServiceImpl::EnableCloud(const std::string &id, const std::map<std::string, int32_t> &switches)
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto user = Account::GetInstance()->GetUserByToken(tokenId);
    auto [status, cloudInfo] = GetCloudInfo(user);
    if (status != SUCCESS) {
        return status;
    }
    cloudInfo.enableCloud = true;
    for (const auto &[bundle, value] : switches) {
        if (!cloudInfo.Exist(bundle)) {
            continue;
        }
        cloudInfo.apps[bundle].cloudSwitch = (value == SWITCH_ON);
    }
    if (!MetaDataManager::GetInstance().SaveMeta(cloudInfo.GetKey(), cloudInfo, true)) {
        return ERROR;
    }
    Execute(GenTask(0, cloudInfo.user, { WORK_CLOUD_INFO_UPDATE, WORK_SCHEMA_UPDATE, WORK_SUB, WORK_DO_CLOUD_SYNC }));
    return SUCCESS;
}

int32_t CloudServiceImpl::DisableCloud(const std::string &id)
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto user = Account::GetInstance()->GetUserByToken(tokenId);
    auto [status, cloudInfo] = GetCloudInfo(user);
    if (status != SUCCESS) {
        return status;
    }
    if (cloudInfo.id != id) {
        ZLOGE("invalid args, [input] id:%{public}s, [exist] id:%{public}s", Anonymous::Change(id).c_str(),
            Anonymous::Change(cloudInfo.id).c_str());
        return ERROR;
    }
    cloudInfo.enableCloud = false;
    if (!MetaDataManager::GetInstance().SaveMeta(cloudInfo.GetKey(), cloudInfo, true)) {
        return ERROR;
    }
    Execute(GenTask(0, cloudInfo.user, { WORK_STOP_CLOUD_SYNC, WORK_RELEASE, WORK_SUB }));
    return SUCCESS;
}

int32_t CloudServiceImpl::ChangeAppSwitch(const std::string &id, const std::string &bundleName, int32_t appSwitch)
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto user = Account::GetInstance()->GetUserByToken(tokenId);
    auto [status, cloudInfo] = GetCloudInfo(user);
    if (status != SUCCESS) {
        return status;
    }
    if (cloudInfo.id != id || !cloudInfo.Exist(bundleName)) {
        ZLOGE("invalid args, [input] id:%{public}s, [exist] id:%{public}s, bundleName:%{public}s",
            Anonymous::Change(id).c_str(), Anonymous::Change(cloudInfo.id).c_str(), bundleName.c_str());
        return ERROR;
    }
    cloudInfo.apps[bundleName].cloudSwitch = (appSwitch == SWITCH_ON);
    if (!MetaDataManager::GetInstance().SaveMeta(cloudInfo.GetKey(), cloudInfo, true)) {
        return ERROR;
    }
    Execute(GenTask(0, cloudInfo.user, { WORK_CLOUD_INFO_UPDATE, WORK_SCHEMA_UPDATE, WORK_SUB }));
    if (cloudInfo.enableCloud && appSwitch == SWITCH_ON) {
        syncManager_.DoCloudSync({ cloudInfo.user, bundleName });
    }
    return SUCCESS;
}

int32_t CloudServiceImpl::DoClean(CloudInfo &cloudInfo, const std::map<std::string, int32_t> &actions)
{
    syncManager_.StopCloudSync(cloudInfo.user);
    auto keys = cloudInfo.GetSchemaKey();
    for (const auto &[bundle, action] : actions) {
        if (!cloudInfo.Exist(bundle)) {
            continue;
        }
        SchemaMeta schemaMeta;
        if (!MetaDataManager::GetInstance().LoadMeta(keys[bundle], schemaMeta, true)) {
            ZLOGE("failed, no schema meta:bundleName:%{public}s", bundle.c_str());
            return ERROR;
        }
        for (const auto &database : schemaMeta.databases) {
            // action
            StoreMetaData meta;
            meta.bundleName = schemaMeta.bundleName;
            meta.storeId = database.name;
            meta.user = std::to_string(cloudInfo.user);
            meta.deviceId = DmAdapter::GetInstance().GetLocalDevice().uuid;
            meta.instanceId = cloudInfo.apps[bundle].instanceId;
            if (!MetaDataManager::GetInstance().LoadMeta(meta.GetKey(), meta)) {
                ZLOGE("failed, no store meta bundleName:%{public}s, storeId:%{public}s", meta.bundleName.c_str(),
                    meta.GetStoreAlias().c_str());
                continue;
            }
            AutoCache::Store store = SyncManager::GetStore(meta, cloudInfo.user, false);
            if (store == nullptr) {
                ZLOGE("store null, storeId:%{public}s", meta.GetStoreAlias().c_str());
                return ERROR;
            }
            auto status = store->Clean({}, action, "");
            if (status != E_OK) {
                ZLOGW("remove device data status:%{public}d, user:%{public}d, bundleName:%{public}s, "
                      "storeId:%{public}s",
                    status, static_cast<int>(cloudInfo.user), meta.bundleName.c_str(), meta.GetStoreAlias().c_str());
                continue;
            }
        }
    }
    return SUCCESS;
}

int32_t CloudServiceImpl::Clean(const std::string &id, const std::map<std::string, int32_t> &actions)
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto user = Account::GetInstance()->GetUserByToken(tokenId);
    auto [status, cloudInfo] = GetCloudInfoFromMeta(user);
    if (status != SUCCESS) {
        ZLOGE("get cloud meta failed user:%{public}d", static_cast<int>(cloudInfo.user));
        return ERROR;
    }
    if (id != cloudInfo.id) {
        ZLOGE("different id, [server] id:%{public}s, [meta] id:%{public}s", Anonymous::Change(cloudInfo.id).c_str(),
            Anonymous::Change(id).c_str());
        return ERROR;
    }
    auto dbActions = ConvertAction(actions);
    if (dbActions.empty()) {
        ZLOGE("invalid actions. id:%{public}s", Anonymous::Change(cloudInfo.id).c_str());
        return ERROR;
    }
    return DoClean(cloudInfo, dbActions);
}

int32_t CloudServiceImpl::CheckNotifyConditions(const std::string &id, const std::string &bundleName,
    CloudInfo &cloudInfo)
{
    if (cloudInfo.id != id) {
        ZLOGE("invalid args, [input] id:%{public}s, [meta] id:%{public}s", Anonymous::Change(id).c_str(),
            Anonymous::Change(cloudInfo.id).c_str());
        return INVALID_ARGUMENT;
    }
    if (!cloudInfo.enableCloud) {
        return CLOUD_DISABLE;
    }
    if (!cloudInfo.Exist(bundleName)) {
        ZLOGE("bundleName:%{public}s is not exist", bundleName.c_str());
        return INVALID_ARGUMENT;
    }
    if (!cloudInfo.apps[bundleName].cloudSwitch) {
        return CLOUD_DISABLE_SWITCH;
    }
    return SUCCESS;
}

std::pair<std::string, std::vector<std::string>> CloudServiceImpl::GetDbInfoFromExtraData(const ExtraData &extraData,
    const SchemaMeta &schemaMeta)
{
    for (auto &db : schemaMeta.databases) {
        if (db.alias != extraData.info.containerName) {
            continue;
        }
        std::vector<std::string> tables;
        for (auto &table : db.tables) {
            const auto &tbs = extraData.info.tables;
            if (std::find(tbs.begin(), tbs.end(), table.alias) == tbs.end()) {
                continue;
            }
            if (extraData.isPrivate()) {
                ZLOGD("private table change, name:%{public}s", Anonymous::Change(table.name).c_str());
                tables.emplace_back(table.name);
            }
            if (extraData.isShared() && !table.sharedTableName.empty()) {
                ZLOGD("sharing table change, name:%{public}s", Anonymous::Change(table.sharedTableName).c_str());
                tables.emplace_back(table.sharedTableName);
            }
        }
        return { db.name, std::move(tables) };
    }
    return { "", {} };
}

int32_t CloudServiceImpl::NotifyDataChange(const std::string &id, const std::string &bundleName)
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto user = Account::GetInstance()->GetUserByToken(tokenId);
    auto [status, cloudInfo] = GetCloudInfoFromMeta(user);
    if (CheckNotifyConditions(id, bundleName, cloudInfo) != E_OK) {
        return INVALID_ARGUMENT;
    }
    syncManager_.DoCloudSync(SyncManager::SyncInfo(cloudInfo.user, bundleName));
    return SUCCESS;
}

int32_t CloudServiceImpl::NotifyDataChange(const std::string &eventId, const std::string &extraData, int32_t userId)
{
    ExtraData exData;
    if (eventId != DATA_CHANGE_EVENT_ID || extraData.empty() || !exData.Unmarshall(extraData)) {
        ZLOGE("invalid args, eventId:%{public}s, user:%{public}d, extraData is %{public}s", eventId.c_str(),
            userId, extraData.empty() ? "empty" : "not empty");
        return INVALID_ARGUMENT;
    }
    std::vector<int32_t> users;
    if (userId != INVALID_USER_ID) {
        users.emplace_back(userId);
    } else {
        Account::GetInstance()->QueryUsers(users);
    }
    for (auto user : users) {
        if (user == DEFAULT_USER) {
            continue;
        }
        auto [status, cloudInfo] = GetCloudInfoFromMeta(user);
        if (CheckNotifyConditions(exData.info.accountId, exData.info.bundleName, cloudInfo) != E_OK) {
            ZLOGD("invalid user:%{public}d", user);
            return INVALID_ARGUMENT;
        }
        auto schemaKey = CloudInfo::GetSchemaKey(user, exData.info.bundleName);
        SchemaMeta schemaMeta;
        if (!MetaDataManager::GetInstance().LoadMeta(schemaKey, schemaMeta, true)) {
            ZLOGE("no exist meta, user:%{public}d", user);
            return INVALID_ARGUMENT;
        }
        auto [storeId, tables] = GetDbInfoFromExtraData(exData, schemaMeta);
        if (storeId.empty()) {
            ZLOGE("invalid data, storeId:%{public}s, tables size:%{public}zu", Anonymous::Change(storeId).c_str(),
                tables.size());
            return INVALID_ARGUMENT;
        }
        syncManager_.DoCloudSync(SyncManager::SyncInfo(cloudInfo.user, exData.info.bundleName, storeId, tables));
    }
    return SUCCESS;
}

int32_t CloudServiceImpl::OnInitialize()
{
    DistributedDB::RuntimeConfig::SetCloudTranslate(std::make_shared<DistributedRdb::RdbCloudDataTranslate>());
    Execute(GenTask(0, 0, { WORK_CLOUD_INFO_UPDATE, WORK_SCHEMA_UPDATE, WORK_SUB }));
    std::vector<int> users;
    Account::GetInstance()->QueryUsers(users);
    for (auto user : users) {
        if (user == DEFAULT_USER) {
            continue;
        }
        Subscription sub;
        sub.userId = user;
        if (!MetaDataManager::GetInstance().LoadMeta(sub.GetKey(), sub, true)) {
            ZLOGE("no exist meta, user:%{public}d", user);
            continue;
        }
        InitSubTask(sub);
    }
    return E_OK;
}

int32_t CloudServiceImpl::OnBind(const BindInfo &info)
{
    if (executor_ != nullptr || info.executors == nullptr) {
        return E_INVALID_ARGS;
    }

    executor_ = std::move(info.executors);
    syncManager_.Bind(executor_);
    return E_OK;
}

int32_t CloudServiceImpl::OnUserChange(uint32_t code, const std::string &user, const std::string &account)
{
    int32_t userId = atoi(user.c_str());
    switch (code) {
        case static_cast<uint32_t>(AccountStatus::DEVICE_ACCOUNT_SWITCHED):
            Execute(GenTask(0, userId, { WORK_CLOUD_INFO_UPDATE, WORK_SCHEMA_UPDATE, WORK_SUB, WORK_DO_CLOUD_SYNC }));
            break;
        case static_cast<uint32_t>(AccountStatus::DEVICE_ACCOUNT_DELETE):
            Execute(GenTask(0, userId, { WORK_STOP_CLOUD_SYNC, WORK_RELEASE }));
            break;
        case static_cast<uint32_t>(AccountStatus::DEVICE_ACCOUNT_UNLOCKED):
            Execute(GenTask(0, userId, { WORK_CLOUD_INFO_UPDATE, WORK_SCHEMA_UPDATE, WORK_SUB, WORK_DO_CLOUD_SYNC }));
            break;
        default:
            break;
    }
    return E_OK;
}

int32_t CloudServiceImpl::Online(const std::string &device)
{
    if (device != DeviceManagerAdapter::CLOUD_DEVICE_UUID) {
        ZLOGI("Not network online");
        return SUCCESS;
    }
    std::vector<int32_t> users;
    Account::GetInstance()->QueryUsers(users);
    if (users.empty()) {
        return SUCCESS;
    }
    auto it = users.begin();
    Execute(GenTask(0, *it, { WORK_CLOUD_INFO_UPDATE, WORK_SCHEMA_UPDATE, WORK_SUB, WORK_DO_CLOUD_SYNC }));
    return SUCCESS;
}

int32_t CloudServiceImpl::Offline(const std::string &device)
{
    if (device != DeviceManagerAdapter::CLOUD_DEVICE_UUID) {
        ZLOGI("Not network offline");
        return SUCCESS;
    }
    std::vector<int32_t> users;
    Account::GetInstance()->QueryUsers(users);
    if (users.empty()) {
        return SUCCESS;
    }
    auto it = users.begin();
    syncManager_.StopCloudSync(*it);
    return SUCCESS;
}

std::pair<int32_t, CloudInfo> CloudServiceImpl::GetCloudInfoFromMeta(int32_t userId)
{
    CloudInfo cloudInfo;
    cloudInfo.user = userId;
    if (!MetaDataManager::GetInstance().LoadMeta(cloudInfo.GetKey(), cloudInfo, true)) {
        ZLOGE("no exist meta, user:%{public}d", cloudInfo.user);
        return { ERROR, cloudInfo };
    }
    return { SUCCESS, cloudInfo };
}

std::pair<int32_t, CloudInfo> CloudServiceImpl::GetCloudInfoFromServer(int32_t userId)
{
    CloudInfo cloudInfo;
    cloudInfo.user = userId;
    auto instance = CloudServer::GetInstance();
    if (instance == nullptr) {
        return { SERVER_UNAVAILABLE, cloudInfo };
    }
    cloudInfo = instance->GetServerInfo(cloudInfo.user);
    if (!cloudInfo.IsValid()) {
        ZLOGE("cloud is empty, user%{public}d", cloudInfo.user);
        return { ERROR, cloudInfo };
    }
    return { SUCCESS, cloudInfo };
}

bool CloudServiceImpl::UpdateCloudInfo(int32_t user)
{
    auto [status, cloudInfo] = GetCloudInfoFromServer(user);
    if (status != SUCCESS) {
        return false;
    }
    CloudInfo oldInfo;
    if (!MetaDataManager::GetInstance().LoadMeta(cloudInfo.GetKey(), oldInfo, true)) {
        MetaDataManager::GetInstance().SaveMeta(cloudInfo.GetKey(), cloudInfo, true);
        return true;
    }
    MetaDataManager::GetInstance().SaveMeta(cloudInfo.GetKey(), cloudInfo, true);
    if (oldInfo.id != cloudInfo.id) {
        ReleaseUserInfo(user);
        ZLOGE("different id, [server] id:%{public}s, [meta] id:%{public}s", Anonymous::Change(cloudInfo.id).c_str(),
            Anonymous::Change(oldInfo.id).c_str());
        std::map<std::string, int32_t> actions;
        for (auto &[bundle, app] : cloudInfo.apps) {
            actions[bundle] = GeneralStore::CleanMode::CLOUD_INFO;
        }
        DoClean(oldInfo, actions);
    }
    return true;
}

bool CloudServiceImpl::UpdateSchema(int32_t user)
{
    auto [status, cloudInfo] = GetCloudInfoFromServer(user);
    if (status != SUCCESS) {
        return false;
    }
    auto keys = cloudInfo.GetSchemaKey();
    for (const auto &[bundle, key] : keys) {
        SchemaMeta schemaMeta;
        std::tie(status, schemaMeta) = GetAppSchemaFromServer(user, bundle);
        if (status != SUCCESS) {
            continue;
        }
        MetaDataManager::GetInstance().SaveMeta(key, schemaMeta, true);
    }
    return true;
}

std::pair<int32_t, SchemaMeta> CloudServiceImpl::GetAppSchemaFromServer(int32_t user, const std::string &bundleName)
{
    SchemaMeta schemaMeta;
    auto instance = CloudServer::GetInstance();
    if (instance == nullptr) {
        return { SERVER_UNAVAILABLE, schemaMeta };
    }
    schemaMeta = instance->GetAppSchema(user, bundleName);
    if (!schemaMeta.IsValid()) {
        ZLOGE("schema is InValid, user:%{public}d, bundleName:%{public}s", user, bundleName.c_str());
        return { ERROR, schemaMeta };
    }
    return { SUCCESS, schemaMeta };
}

ExecutorPool::Task CloudServiceImpl::GenTask(int32_t retry, int32_t user, Handles handles)
{
    return [this, retry, user, works = std::move(handles)]() mutable {
        auto executor = executor_;
        if (retry >= RETRY_TIMES || executor == nullptr || works.empty()) {
            return;
        }
        if (!DmAdapter::GetInstance().IsNetworkAvailable()) {
            return;
        }
        bool finished = true;
        std::vector<int32_t> users;
        if (user == 0) {
            auto account = Account::GetInstance();
            finished = !(account == nullptr) && account->QueryUsers(users);
        } else {
            users.push_back(user);
        }

        auto handle = works.front();
        for (auto user : users) {
            if (user == 0 || !Account::GetInstance()->IsVerified(user)) {
                continue;
            }
            finished = (this->*handle)(user) && finished;
        }
        if (!finished || users.empty()) {
            executor->Schedule(std::chrono::seconds(RETRY_INTERVAL), GenTask(retry + 1, user, std::move(works)));
            return;
        }
        works.pop_front();
        if (!works.empty()) {
            executor->Execute(GenTask(retry, user, std::move(works)));
        }
    };
}

std::pair<int32_t, SchemaMeta> CloudServiceImpl::GetSchemaMeta(int32_t userId, const std::string &bundleName,
    int32_t instanceId)
{
    SchemaMeta schemaMeta;
    auto [status, cloudInfo] = GetCloudInfoFromMeta(userId);
    if (status != SUCCESS) {
        // GetCloudInfo has print the log info. so we don`t need print again.
        return { status, schemaMeta };
    }
    if (!bundleName.empty() && !cloudInfo.Exist(bundleName, instanceId)) {
        ZLOGD("bundleName:%{public}s instanceId:%{public}d is not exist", bundleName.c_str(), instanceId);
        return { ERROR, schemaMeta };
    }
    std::string schemaKey = cloudInfo.GetSchemaKey(bundleName, instanceId);
    if (MetaDataManager::GetInstance().LoadMeta(schemaKey, schemaMeta, true)) {
        return { SUCCESS, schemaMeta };
    }
    if (!Account::GetInstance()->IsVerified(userId)) {
        return { ERROR, schemaMeta };
    }
    std::tie(status, schemaMeta) = GetAppSchemaFromServer(userId, bundleName);
    if (status != SUCCESS) {
        return { status, schemaMeta };
    }
    MetaDataManager::GetInstance().SaveMeta(schemaKey, schemaMeta, true);
    return { SUCCESS, schemaMeta };
}

std::pair<int32_t, CloudInfo> CloudServiceImpl::GetCloudInfo(int32_t userId)
{
    auto [status, cloudInfo] = GetCloudInfoFromMeta(userId);
    if (status == SUCCESS) {
        return { status, cloudInfo };
    }
    if (!Account::GetInstance()->IsVerified(userId)) {
        ZLOGW("user:%{public}d is locked!", userId);
        return { ERROR, cloudInfo };
    }
    std::tie(status, cloudInfo) = GetCloudInfoFromServer(userId);
    if (status == SUCCESS) {
        return { status, cloudInfo };
    }
    MetaDataManager::GetInstance().SaveMeta(cloudInfo.GetKey(), cloudInfo, true);
    return { SUCCESS, cloudInfo };
}

int32_t CloudServiceImpl::CloudStatic::OnAppUninstall(const std::string &bundleName, int32_t user, int32_t index)
{
    MetaDataManager::GetInstance().DelMeta(Subscription::GetRelationKey(user, bundleName), true);
    MetaDataManager::GetInstance().DelMeta(CloudInfo::GetSchemaKey(user, bundleName, index), true);
    return E_OK;
}

void CloudServiceImpl::GetSchema(const Event &event)
{
    auto &rdbEvent = static_cast<const CloudEvent &>(event);
    auto &storeInfo = rdbEvent.GetStoreInfo();
    ZLOGD("Start GetSchema, bundleName:%{public}s, storeName:%{public}s, instanceId:%{public}d",
        storeInfo.bundleName.c_str(), Anonymous::Change(storeInfo.storeName).c_str(), storeInfo.instanceId);
    GetSchemaMeta(storeInfo.user, storeInfo.bundleName, storeInfo.instanceId);
}

void CloudServiceImpl::CloudShare(const Event &event)
{
    auto &cloudShareEvent = static_cast<const CloudShareEvent &>(event);
    auto &storeInfo = cloudShareEvent.GetStoreInfo();
    auto query = cloudShareEvent.GetQuery();
    auto callback = cloudShareEvent.GetCallback();
    if (query == nullptr) {
        ZLOGE("query is null, bundleName:%{public}s, storeName:%{public}s, instanceId:%{public}d",
            storeInfo.bundleName.c_str(), Anonymous::Change(storeInfo.storeName).c_str(), storeInfo.instanceId);
        if (callback) {
            callback(GeneralError::E_ERROR, nullptr);
        }
    }
    ZLOGD("Start PreShare, bundleName:%{public}s, storeName:%{public}s, instanceId:%{public}d",
        storeInfo.bundleName.c_str(), Anonymous::Change(storeInfo.storeName).c_str(), storeInfo.instanceId);
    auto [status, cursor] = PreShare(storeInfo, *query);

    if (callback) {
        callback(status, cursor);
    }
}

std::pair<int32_t, std::shared_ptr<DistributedData::Cursor>> CloudServiceImpl::PreShare(
    const CloudEvent::StoreInfo& storeInfo, GenQuery& query)
{
    StoreMetaData meta;
    meta.bundleName = storeInfo.bundleName;
    meta.storeId = storeInfo.storeName;
    meta.user = std::to_string(storeInfo.user);
    meta.deviceId = DmAdapter::GetInstance().GetLocalDevice().uuid;
    meta.instanceId = storeInfo.instanceId;
    if (!MetaDataManager::GetInstance().LoadMeta(meta.GetKey(), meta)) {
        ZLOGE("failed, no store meta bundleName:%{public}s, storeId:%{public}s", meta.bundleName.c_str(),
            meta.GetStoreAlias().c_str());
        return { GeneralError::E_ERROR, nullptr };
    }
    AutoCache::Store store = SyncManager::GetStore(meta, storeInfo.user, true);
    if (store == nullptr) {
        ZLOGE("store null, storeId:%{public}s", meta.GetStoreAlias().c_str());
        return { GeneralError::E_ERROR, nullptr };
    }
    return { GeneralError::E_OK, store->PreSharing(query) };
}

bool CloudServiceImpl::ReleaseUserInfo(int32_t user)
{
    auto instance = CloudServer::GetInstance();
    if (instance == nullptr) {
        return true;
    }
    instance->ReleaseUserInfo(user);
    return true;
}

bool CloudServiceImpl::DoCloudSync(int32_t user)
{
    syncManager_.DoCloudSync(user);
    return true;
}

bool CloudServiceImpl::StopCloudSync(int32_t user)
{
    syncManager_.StopCloudSync(user);
    return true;
}

bool CloudServiceImpl::DoSubscribe(int32_t user)
{
    Subscription sub;
    sub.userId = user;
    MetaDataManager::GetInstance().LoadMeta(sub.GetKey(), sub, true);
    if (CloudServer::GetInstance() == nullptr) {
        ZLOGI("not support cloud server");
        return true;
    }

    CloudInfo cloudInfo;
    cloudInfo.user = sub.userId;
    auto exits = MetaDataManager::GetInstance().LoadMeta(cloudInfo.GetKey(), cloudInfo, true);
    if (!exits) {
        ZLOGW("error, there is no cloud info for user(%{public}d)", sub.userId);
        return false;
    }
    if (!sub.id.empty() && sub.id != cloudInfo.id) {
        CleanSubscription(sub);
        sub.id.clear();
        sub.expiresTime.clear();
    }

    ZLOGD("begin cloud:%{public}d user:%{public}d apps:%{public}zu", cloudInfo.enableCloud, sub.userId,
        cloudInfo.apps.size());
    auto onThreshold = duration_cast<milliseconds>((system_clock::now() + hours(EXPIRE_INTERVAL)).time_since_epoch());
    auto offThreshold = duration_cast<milliseconds>(system_clock::now().time_since_epoch());
    std::map<std::string, std::vector<SchemaMeta::Database>> subDbs;
    std::map<std::string, std::vector<SchemaMeta::Database>> unsubDbs;
    for (auto &[bundle, app] : cloudInfo.apps) {
        auto enabled = cloudInfo.enableCloud && app.cloudSwitch;
        auto &dbs = enabled ? subDbs : unsubDbs;
        auto it = sub.expiresTime.find(bundle);
        // cloud is enabled, but the subscription won't expire
        if (enabled && (it != sub.expiresTime.end() && it->second >= static_cast<uint64_t>(onThreshold.count()))) {
            continue;
        }
        // cloud is disabled, we don't care the subscription which was expired or didn't subscribe.
        if (!enabled && (it == sub.expiresTime.end() || it->second <= static_cast<uint64_t>(offThreshold.count()))) {
            continue;
        }

        SchemaMeta schemaMeta;
        exits = MetaDataManager::GetInstance().LoadMeta(cloudInfo.GetSchemaKey(bundle), schemaMeta, true);
        if (exits) {
            dbs.insert_or_assign(bundle, std::move(schemaMeta.databases));
        }
    }

    ZLOGI("cloud switch:%{public}d user%{public}d, sub:%{public}zu, unsub:%{public}zu", cloudInfo.enableCloud,
        sub.userId, subDbs.size(), unsubDbs.size());
    ZLOGD("Subscribe user%{public}d details:%{public}s", sub.userId, Serializable::Marshall(subDbs).c_str());
    ZLOGD("Unsubscribe user%{public}d details:%{public}s", sub.userId, Serializable::Marshall(unsubDbs).c_str());
    CloudServer::GetInstance()->Subscribe(sub.userId, subDbs);
    CloudServer::GetInstance()->Unsubscribe(sub.userId, unsubDbs);
    return subDbs.empty() && unsubDbs.empty();
}

void CloudServiceImpl::CleanSubscription(Subscription &sub)
{
    ZLOGD("id:%{public}s, size:%{public}zu", Anonymous::Change(sub.id).c_str(), sub.expiresTime.size());
    MetaDataManager::GetInstance().DelMeta(sub.GetKey(), true);
    for (const auto &[bundle, expireTime] : sub.expiresTime) {
        MetaDataManager::GetInstance().DelMeta(sub.GetRelationKey(bundle), true);
    }
}

void CloudServiceImpl::Execute(Task task)
{
    auto executor = executor_;
    if (executor == nullptr) {
        return;
    }
    executor->Execute(std::move(task));
}

std::map<std::string, int32_t> CloudServiceImpl::ConvertAction(const std::map<std::string, int32_t> &actions)
{
    std::map<std::string, int32_t> genActions;
    for (const auto &[bundleName, action] : actions) {
        switch (action) {
            case CloudService::Action::CLEAR_CLOUD_INFO:
                genActions.emplace(bundleName, GeneralStore::CleanMode::CLOUD_INFO);
                break;
            case CloudService::Action::CLEAR_CLOUD_DATA_AND_INFO:
                genActions.emplace(bundleName, GeneralStore::CleanMode::CLOUD_DATA);
                break;
            default:
                ZLOGE("invalid action. action:%{public}d, bundleName:%{public}s", action, bundleName.c_str());
                return {};
        }
    }
    return genActions;
}

std::pair<int32_t, std::vector<NativeRdb::ValuesBucket>> CloudServiceImpl::AllocResourceAndShare(
    const std::string& storeId, const DistributedRdb::PredicatesMemo& predicates,
    const std::vector<std::string>& columns, const Participants& participants)
{
    auto tokenId = IPCSkeleton::GetCallingTokenID();
    auto hapInfo = GetHapInfo(tokenId);
    if (hapInfo.bundleName.empty() || hapInfo.user == INVALID_USER_ID) {
        ZLOGE("bundleName is empty or invalid user, user:%{public}d, storeId:%{public}s", hapInfo.user,
            Anonymous::Change(storeId).c_str());
        return { E_ERROR, {} };
    }
    if (predicates.tables_.empty()) {
        ZLOGE("invalid args, tables size:%{public}zu, storeId:%{public}s", predicates.tables_.size(),
            Anonymous::Change(storeId).c_str());
        return { E_INVALID_ARGS, {} };
    }
    auto memo = std::make_shared<DistributedRdb::PredicatesMemo>(predicates);
    CloudEvent::StoreInfo storeInfo;
    storeInfo.bundleName = hapInfo.bundleName;
    storeInfo.tokenId = tokenId;
    storeInfo.user = hapInfo.user;
    storeInfo.storeName = storeId;
    std::shared_ptr<GenQuery> query;
    MakeQueryEvent::Callback asyncCallback = [&query](std::shared_ptr<GenQuery> genQuery) {
        query = genQuery;
    };
    auto evt = std::make_unique<MakeQueryEvent>(storeInfo, memo, columns, asyncCallback);
    EventCenter::GetInstance().PostEvent(std::move(evt));
    if (query == nullptr) {
        ZLOGE("query is null, storeId:%{public}s,", Anonymous::Change(storeId).c_str());
        return { E_ERROR, {} };
    }
    auto [status, cursor] = PreShare(storeInfo, *query);
    if (status != GeneralError::E_OK || cursor == nullptr) {
        ZLOGE("PreShare fail, storeId:%{public}s, status:%{public}d", Anonymous::Change(storeId).c_str(), status);
        return { E_ERROR, {} };
    }
    auto valueBuckets = ConvertCursor(cursor);
    Results results;
    for (auto &valueBucket : valueBuckets) {
        NativeRdb::ValueObject object;
        if (!valueBucket.GetObject(DistributedRdb::Field::SHARING_RESOURCE_FIELD, object)) {
            continue;
        }
        std::string shareRes;
        if (object.GetString(shareRes) != E_OK) {
            continue;
        }
        Share(shareRes, participants, results);
    }
    return { SUCCESS, std::move(valueBuckets) };
}

std::vector<NativeRdb::ValuesBucket> CloudServiceImpl::ConvertCursor(std::shared_ptr<Cursor> cursor) const
{
    std::vector<NativeRdb::ValuesBucket> valueBuckets;
    int32_t count = cursor->GetCount();
    valueBuckets.reserve(count);
    auto err = cursor->MoveToFirst();
    while (err == E_OK && count > 0) {
        VBucket entry;
        err = cursor->GetEntry(entry);
        if (err != E_OK) {
            break;
        }
        NativeRdb::ValuesBucket bucket;
        for (auto &[key, value] : entry) {
            NativeRdb::ValueObject object;
            DistributedData::Convert(std::move(value), object.value);
            bucket.values_.insert_or_assign(key, std::move(object));
        }
        valueBuckets.emplace_back(std::move(bucket));
        err = cursor->MoveToNext();
        count--;
    }
    return valueBuckets;
}

CloudServiceImpl::HapInfo CloudServiceImpl::GetHapInfo(uint32_t tokenId)
{
    HapTokenInfo tokenInfo;
    int errCode = AccessTokenKit::GetHapTokenInfo(tokenId, tokenInfo);
    if (errCode != RET_SUCCESS) {
        ZLOGE("GetHapTokenInfo error:%{public}d, tokenId:0x%{public}x", errCode, tokenId);
        return { INVALID_USER_ID, -1, "" };
    }
    return { tokenInfo.userID, tokenInfo.instIndex, tokenInfo.bundleName };
}

int32_t CloudServiceImpl::Share(const std::string &sharingRes, const Participants &participants, Results &results)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, sharingRes:%{public}s", Anonymous::Change(sharingRes).c_str());
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    results = instance->Share(hapInfo.user, hapInfo.bundleName, sharingRes, Convert(participants));
    int32_t status = std::get<0>(results);
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

int32_t CloudServiceImpl::Unshare(const std::string &sharingRes, const Participants &participants, Results &results)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, sharingRes:%{public}s", Anonymous::Change(sharingRes).c_str());
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    results = instance->Unshare(hapInfo.user, hapInfo.bundleName, sharingRes, Convert(participants));
    int32_t status = std::get<0>(results);
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

int32_t CloudServiceImpl::Exit(const std::string &sharingRes, std::pair<int32_t, std::string> &result)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, sharingRes:%{public}s", Anonymous::Change(sharingRes).c_str());
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    result = instance->Exit(hapInfo.user, hapInfo.bundleName, sharingRes);
    int32_t status = result.first;
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

int32_t CloudServiceImpl::ChangePrivilege(const std::string &sharingRes, const Participants &participants,
    Results &results)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, sharingRes:%{public}s", Anonymous::Change(sharingRes).c_str());
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    results = instance->ChangePrivilege(hapInfo.user, hapInfo.bundleName, sharingRes, Convert(participants));
    int32_t status = std::get<0>(results);
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

int32_t CloudServiceImpl::Query(const std::string &sharingRes, QueryResults &results)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, sharingRes:%{public}s", Anonymous::Change(sharingRes).c_str());
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    auto queryResults = instance->Query(hapInfo.user, hapInfo.bundleName, sharingRes);
    results = Convert(queryResults);
    int32_t status = std::get<0>(queryResults);
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

int32_t CloudServiceImpl::QueryByInvitation(const std::string &invitation, QueryResults &results)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, invitation:%{public}s", Anonymous::Change(invitation).c_str());
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    auto queryResults = instance->QueryByInvitation(hapInfo.user, hapInfo.bundleName, invitation);
    results = Convert(queryResults);
    int32_t status = std::get<0>(queryResults);
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

int32_t CloudServiceImpl::ConfirmInvitation(const std::string &invitation, int32_t confirmation,
    std::tuple<int32_t, std::string, std::string> &result)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, invitation:%{public}s, confirmation:%{public}d",
            Anonymous::Change(invitation).c_str(), confirmation);
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    result = instance->ConfirmInvitation(hapInfo.user, hapInfo.bundleName, invitation, confirmation);
    int32_t status = std::get<0>(result);
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

int32_t CloudServiceImpl::ChangeConfirmation(const std::string &sharingRes, int32_t confirmation,
    std::pair<int32_t, std::string> &result)
{
    auto hapInfo = GetHapInfo(IPCSkeleton::GetCallingTokenID());
    if (hapInfo.bundleName.empty()) {
        ZLOGE("bundleName is empty, sharingRes:%{public}s", Anonymous::Change(sharingRes).c_str());
        return E_ERROR;
    }
    auto instance = GetSharingHandle(hapInfo);
    if (instance == nullptr) {
        return NOT_SUPPORT;
    }
    result = instance->ChangeConfirmation(hapInfo.user, hapInfo.bundleName, sharingRes, confirmation);
    int32_t status = result.first;
    ZLOGD("status:%{public}d", status);
    return Convert(static_cast<CenterCode>(status));
}

std::shared_ptr<SharingCenter> CloudServiceImpl::GetSharingHandle(const HapInfo &hapInfo)
{
    auto instance = CloudServer::GetInstance();
    if (instance == nullptr) {
        return nullptr;
    }
    auto handle = instance->ConnectSharingCenter(hapInfo.user, hapInfo.bundleName);
    return handle;
}

ExecutorPool::Task CloudServiceImpl::GenSubTask(Task task, int32_t user)
{
    return [this, user, work = std::move(task)] () {
        {
            std::lock_guard<decltype(mutex_)> lock(mutex_);
            subTask_ = ExecutorPool::INVALID_TASK_ID;
        }
        auto [status, cloudInfo] = GetCloudInfoFromMeta(user);
        if (status != SUCCESS || !cloudInfo.enableCloud || cloudInfo.IsAllSwitchOff()) {
            ZLOGW("[sub task] all switch off, status:%{public}d user:%{public}d enableCloud:%{public}d",
                status, user, cloudInfo.enableCloud);
            return;
        }
        work();
    };
}

void CloudServiceImpl::InitSubTask(const Subscription &sub)
{
    auto expire = sub.GetMinExpireTime();
    if (expire == INVALID_SUB_TIME) {
        ZLOGW("expire: %{public}" PRIu64, expire);
        return;
    }
    auto executor = executor_;
    if (executor == nullptr) {
        return;
    }
    ZLOGI("Subscription Info, subTask:%{public}llu, user:%{public}d", subTask_, sub.userId);
    expire = expire - TIME_BEFORE_SUB; // before 12 hours
    auto now = static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
    Duration delay = expire > now ? milliseconds(expire - now) : milliseconds(0);
    std::lock_guard<decltype(mutex_)> lock(mutex_);
    if (subTask_ != ExecutorPool::INVALID_TASK_ID) {
        if (expire < expireTime_) {
            subTask_ = executor->Reset(subTask_, delay);
            expireTime_ = expire > now ? expire : now;
        }
        return;
    }
    subTask_ = executor->Schedule(delay, GenSubTask(GenTask(0, sub.userId), sub.userId));
    expireTime_ = expire > now ? expire : now;
}

} // namespace OHOS::CloudData