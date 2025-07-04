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

#ifndef OHOS_DISTRIBUTED_DATA_SERVICES_CLOUD_CLOUD_SERVICE_IMPL_H
#define OHOS_DISTRIBUTED_DATA_SERVICES_CLOUD_CLOUD_SERVICE_IMPL_H

#include <mutex>
#include <queue>

#include "cloud/cloud_event.h"
#include "cloud/cloud_extra_data.h"
#include "cloud/cloud_info.h"
#include "cloud_notifier_proxy.h"
#include "cloud/schema_meta.h"
#include "cloud/sharing_center.h"
#include "cloud/subscription.h"
#include "cloud_service_stub.h"
#include "dfx/dfx_types.h"
#include "feature/static_acts.h"
#include "store/general_store.h"
#include "sync_manager.h"
#include "values_bucket.h"

namespace OHOS::CloudData {
using namespace DistributedRdb;
class CloudServiceImpl : public CloudServiceStub {
public:
    using CloudLastSyncInfo = DistributedData::CloudLastSyncInfo;
    using StoreMetaData = DistributedData::StoreMetaData;
    using StoreInfo = DistributedData::StoreInfo;
    CloudServiceImpl();
    ~CloudServiceImpl() = default;
    int32_t EnableCloud(const std::string &id, const std::map<std::string, int32_t> &switches) override;
    int32_t DisableCloud(const std::string &id) override;
    int32_t ChangeAppSwitch(const std::string &id, const std::string &bundleName, int32_t appSwitch) override;
    int32_t Clean(const std::string &id, const std::map<std::string, int32_t> &actions) override;
    int32_t NotifyDataChange(const std::string &id, const std::string &bundleName) override;
    int32_t NotifyDataChange(const std::string &eventId, const std::string &extraData, int32_t userId) override;
    std::pair<int32_t, std::map<std::string, StatisticInfos>> QueryStatistics(
        const std::string &id, const std::string &bundleName, const std::string &storeId) override;
    std::pair<int32_t, QueryLastResults> QueryLastSyncInfo(
        const std::string &id, const std::string &bundleName, const std::string &storeId) override;
    int32_t SetGlobalCloudStrategy(Strategy strategy, const std::vector<CommonType::Value> &values) override;
    int32_t CloudSync(const std::string &bundleName, const std::string &storeId, const Option &option,
        const AsyncDetail &async) override;
    int32_t InitNotifier(sptr<IRemoteObject> notifier) override;

    std::pair<int32_t, std::vector<NativeRdb::ValuesBucket>> AllocResourceAndShare(const std::string &storeId,
        const DistributedRdb::PredicatesMemo &predicates, const std::vector<std::string> &columns,
        const Participants &participants) override;
    int32_t Share(const std::string &sharingRes, const Participants &participants, Results &results) override;
    int32_t Unshare(const std::string &sharingRes, const Participants &participants, Results &results) override;
    int32_t Exit(const std::string &sharingRes, std::pair<int32_t, std::string> &result) override;
    int32_t ChangePrivilege(const std::string &sharingRes, const Participants &participants, Results &results) override;
    int32_t Query(const std::string &sharingRes, QueryResults &results) override;
    int32_t QueryByInvitation(const std::string &invitation, QueryResults &results) override;
    int32_t ConfirmInvitation(const std::string &invitation, int32_t confirmation,
        std::tuple<int32_t, std::string, std::string> &result) override;
    int32_t ChangeConfirmation(
        const std::string &sharingRes, int32_t confirmation, std::pair<int32_t, std::string> &result) override;

    int32_t SetCloudStrategy(Strategy strategy, const std::vector<CommonType::Value> &values) override;

    int32_t OnInitialize() override;
    int32_t OnBind(const BindInfo &info) override;
    int32_t OnUserChange(uint32_t code, const std::string &user, const std::string &account) override;
    int32_t OnReady(const std::string &device) override;
    int32_t Offline(const std::string &device) override;
    int32_t OnScreenUnlocked(int32_t user) override;

private:
    using StaticActs = DistributedData::StaticActs;
    class CloudStatic : public StaticActs {
    public:
        ~CloudStatic() override{};
        int32_t OnAppUninstall(const std::string &bundleName, int32_t user, int32_t index) override;
        int32_t OnAppInstall(const std::string &bundleName, int32_t user, int32_t index) override;
        int32_t OnAppUpdate(const std::string &bundleName, int32_t user, int32_t index) override;
    private:
        bool CloudDriverCheck(const std::string &bundleName, int32_t user);
    };
    class Factory {
    public:
        Factory() noexcept;
        ~Factory();

    private:
        std::shared_ptr<CloudServiceImpl> product_;
        std::shared_ptr<CloudStatic> staticActs_;
    };
    static Factory factory_;
    enum class CloudSyncScene {
        ENABLE_CLOUD = 0,
        DISABLE_CLOUD = 1,
        SWITCH_ON = 2,
        SWITCH_OFF = 3,
        QUERY_SYNC_INFO = 4,
        USER_CHANGE = 5,
        USER_UNLOCK = 6,
        NETWORK_RECOVERY = 7,
        SERVICE_INIT = 8,
        ACCOUNT_STOP = 9,
    };

    using Database = DistributedData::Database;
    using CloudInfo = DistributedData::CloudInfo;
    using SchemaMeta = DistributedData::SchemaMeta;
    using Event = DistributedData::Event;
    using CloudEvent = DistributedData::CloudEvent;
    using Subscription = DistributedData::Subscription;
    using Handle = bool (CloudServiceImpl::*)(int32_t, CloudSyncScene);
    using Handles = std::deque<Handle>;
    using Task = ExecutorPool::Task;
    using TaskId = ExecutorPool::TaskId;
    using Duration = ExecutorPool::Duration;
    using AutoCache = DistributedData::AutoCache;

    struct HapInfo {
        int32_t user;
        int32_t instIndex;
        std::string bundleName;
    };

    struct SyncAgent {
        SyncAgent() = default;
        sptr<CloudNotifierProxy> notifier_;
    };

    static std::map<std::string, int32_t> ConvertAction(const std::map<std::string, int32_t> &actions);
    static HapInfo GetHapInfo(uint32_t tokenId);
    static std::string GetDfxFaultType(CloudSyncScene scene);

    static constexpr uint64_t INVALID_SUB_TIME = 0;
    static constexpr int32_t RETRY_TIMES = 3;
    static constexpr int32_t RETRY_INTERVAL = 60;
    static constexpr int32_t EXPIRE_INTERVAL = 2 * 24; // 2 day
    static constexpr int32_t WAIT_TIME = 30;           // 30 seconds
    static constexpr int32_t DEFAULT_USER = 0;
    static constexpr int32_t TIME_BEFORE_SUB = 12 * 60 * 60 * 1000;  // 12hours, ms
    static constexpr int32_t SUBSCRIPTION_INTERVAL = 60 * 60 * 1000; // 1hours

    bool UpdateCloudInfo(int32_t user, CloudSyncScene scene);
    bool UpdateSchema(int32_t user, CloudSyncScene scene);
    bool DoSubscribe(int32_t user, CloudSyncScene scene);
    bool ReleaseUserInfo(int32_t user, CloudSyncScene scene);
    bool DoCloudSync(int32_t user, CloudSyncScene scene);
    bool StopCloudSync(int32_t user, CloudSyncScene scene);
    bool CleanWaterVersion(int32_t user);

    static std::pair<int32_t, CloudInfo> GetCloudInfo(int32_t userId);
    static std::pair<int32_t, CloudInfo> GetCloudInfoFromMeta(int32_t userId);
    static std::pair<int32_t, CloudInfo> GetCloudInfoFromServer(int32_t userId);
    static int32_t UpdateCloudInfoFromServer(int32_t user);
    static std::pair<int32_t, SchemaMeta> GetAppSchemaFromServer(int32_t user, const std::string &bundleName);
    static Details HandleGenDetails(const DistributedData::GenDetails &details);

    void OnAsyncComplete(uint32_t tokenId, uint32_t seqNum, Details &&result);
    std::pair<int32_t, SchemaMeta> GetSchemaMeta(int32_t userId, const std::string &bundleName, int32_t instanceId);
    void UpgradeSchemaMeta(int32_t user, const SchemaMeta &schemaMeta);
    std::map<std::string, StatisticInfos> ExecuteStatistics(
        const std::string &storeId, const CloudInfo &cloudInfo, const SchemaMeta &schemaMeta);
    StatisticInfos QueryStatistics(const StoreMetaData &storeMetaData, const DistributedData::Database &database);
    std::pair<bool, StatisticInfo> QueryTableStatistic(const std::string &tableName, AutoCache::Store store);
    std::string BuildStatisticSql(const std::string &tableName);

    void GetSchema(const Event &event);
    void CloudShare(const Event &event);
    void DoSync(const Event &event);

    Task GenTask(int32_t retry, int32_t user, CloudSyncScene scene, Handles handles = { WORK_SUB });
    Task GenSubTask(Task task, int32_t user);
    void InitSubTask(const Subscription &sub, uint64_t minInterval = 0);
    void Execute(Task task);
    void CleanSubscription(Subscription &sub);
    int32_t DoClean(const CloudInfo &cloudInfo, const std::map<std::string, int32_t> &actions);
    void DoClean(int32_t user, const SchemaMeta &schemaMeta, int32_t action);
    std::pair<int32_t, std::shared_ptr<DistributedData::Cursor>> PreShare(
        const StoreInfo &storeInfo, DistributedData::GenQuery &query);
    std::vector<NativeRdb::ValuesBucket> ConvertCursor(std::shared_ptr<DistributedData::Cursor> cursor) const;
    int32_t CheckNotifyConditions(const std::string &id, const std::string &bundleName, CloudInfo &cloudInfo);
    std::map<std::string, std::vector<std::string>> GetDbInfoFromExtraData(
        const DistributedData::ExtraData &extraData, const SchemaMeta &schemaMeta);
    std::shared_ptr<DistributedData::SharingCenter> GetSharingHandle(const HapInfo &hapInfo);
    bool GetStoreMetaData(StoreMetaData &meta);
    bool DoKvCloudSync(int32_t userId, const std::string &bundleName = "", int32_t triggerMode = 0);

    using SaveStrategy = int32_t (*)(const std::vector<CommonType::Value> &values, const HapInfo &hapInfo);
    static const SaveStrategy STRATEGY_SAVERS[Strategy::STRATEGY_BUTT];
    static int32_t SaveNetworkStrategy(const std::vector<CommonType::Value> &values, const HapInfo &hapInfo);
    static void Report(const std::string &faultType, DistributedDataDfx::Fault errCode, const std::string &bundleName,
        const std::string &appendix);

    static std::pair<int32_t, SchemaMeta> GetSchemaFromHap(const HapInfo &hapInfo);
    static int32_t UpdateSchemaFromHap(const HapInfo &hapInfo);
    static int32_t UpdateSchemaFromServer(int32_t user);
    static int32_t UpdateSchemaFromServer(const CloudInfo &cloudInfo, int32_t user);
    static void UpdateE2eeEnable(const std::string &schemaKey, bool newE2eeEnable, const std::string &bundleName);
    static void UpdateClearWaterMark(
        const HapInfo &hapInfo, const SchemaMeta &newSchemaMeta, const SchemaMeta &schemaMeta);
    QueryLastResults AssembleLastResults(const std::vector<Database> &databases,
                                         const std::map<std::string, CloudLastSyncInfo> &lastSyncInfos);

    std::shared_ptr<ExecutorPool> executor_;
    SyncManager syncManager_;
    std::mutex mutex_;
    std::mutex rwMetaMutex_;
    TaskId subTask_ = ExecutorPool::INVALID_TASK_ID;
    uint64_t expireTime_ = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count());
    ConcurrentMap<uint32_t, SyncAgent> syncAgents_;

    static constexpr Handle WORK_CLOUD_INFO_UPDATE = &CloudServiceImpl::UpdateCloudInfo;
    static constexpr Handle WORK_SCHEMA_UPDATE = &CloudServiceImpl::UpdateSchema;
    static constexpr Handle WORK_SUB = &CloudServiceImpl::DoSubscribe;
    static constexpr Handle WORK_RELEASE = &CloudServiceImpl::ReleaseUserInfo;
    static constexpr Handle WORK_DO_CLOUD_SYNC = &CloudServiceImpl::DoCloudSync;
    static constexpr Handle WORK_STOP_CLOUD_SYNC = &CloudServiceImpl::StopCloudSync;
};
} // namespace OHOS::CloudData

#endif // OHOS_DISTRIBUTED_DATA_SERVICES_CLOUD_CLOUD_SERVICE_IMPL_H