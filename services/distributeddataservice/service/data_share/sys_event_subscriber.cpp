/*
* Copyright (c) 2024 Huawei Device Co., Ltd.
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
#define LOG_TAG "SysEventSubscriber"
#include "sys_event_subscriber.h"

#include "common_event_manager.h"
#include "common_event_support.h"
#include "log_print.h"
#include "proxy_data_manager.h"

namespace OHOS::DataShare {
SysEventSubscriber::SysEventSubscriber(const EventFwk::CommonEventSubscribeInfo& info)
    : CommonEventSubscriber(info)
{
    callbacks_ = {
        { EventFwk::CommonEventSupport::COMMON_EVENT_BUNDLE_SCAN_FINISHED,
            &SysEventSubscriber::OnBMSReady }
        };
    installCallbacks_ = {
        { EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED,
            &SysEventSubscriber::OnAppInstall },
        { EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED,
            &SysEventSubscriber::OnAppUninstall }
    };
}

void SysEventSubscriber::OnReceiveEvent(const EventFwk::CommonEventData& event)
{
    EventFwk::Want want = event.GetWant();
    std::string action = want.GetAction();
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED ||
        action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        std::string bundleName = want.GetElement().GetBundleName();
        int32_t userId = want.GetIntParam(USER_ID, -1);
        int32_t appIndex = want.GetIntParam(APP_INDEX, 0);
        bool isCrossAppSharedConfig = want.GetBoolParam(CROSS_APP_SHARED_CONFIG, false);
        ZLOGI("bundleName:%{public}s, user:%{public}d, appIndex:%{public}d, isCrossAppSharedConfig:%{public}d",
            bundleName.c_str(), userId, appIndex, isCrossAppSharedConfig);
        auto installEvent = installCallbacks_.find(action);
        if (installEvent != installCallbacks_.end()) {
            (this->*(installEvent->second))(bundleName, userId, appIndex, isCrossAppSharedConfig);
        }
    }
    auto it = callbacks_.find(action);
    if (it != callbacks_.end()) {
        (this->*(it->second))();
    }
}

void SysEventSubscriber::OnBMSReady()
{
    NotifyDataShareReady();
}

void SysEventSubscriber::OnAppInstall(const std::string &bundleName,
    int32_t userId, int32_t appIndex, bool isCrossAppSharedConfig)
{
    ZLOGI("%{public}s installed, userId: %{public}d, appIndex: %{public}d", bundleName.c_str(), userId, appIndex);
    uint32_t tokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    if (isCrossAppSharedConfig) {
        ProxyDataManager::GetInstance().OnAppInstall(bundleName, userId, appIndex, tokenId);
    }
}

void SysEventSubscriber::OnAppUninstall(const std::string &bundleName,
    int32_t userId, int32_t appIndex, bool isCrossAppSharedConfig)
{
    ZLOGI("%{public}s uninstalled, userId: %{public}d, appIndex: %{public}d", bundleName.c_str(), userId, appIndex);
    uint32_t tokenId = Security::AccessToken::AccessTokenKit::GetHapTokenID(userId, bundleName, appIndex);
    ProxyDataManager::GetInstance().OnAppUninstall(bundleName, userId, appIndex, tokenId);
}

void SysEventSubscriber::NotifyDataShareReady()
{
    AAFwk::Want want;
    want.SetAction("usual.event.DATA_SHARE_READY");
    EventFwk::CommonEventData CommonEventData { want };
    EventFwk::CommonEventPublishInfo publishInfo;
    publishInfo.SetSticky(true);
    if (!EventFwk::CommonEventManager::PublishCommonEvent(CommonEventData, publishInfo)) {
        ZLOGE("Notify dataShare ready failed.");
        return;
    }
    ZLOGI("Notify dataShare ready succeed.");
}
}
