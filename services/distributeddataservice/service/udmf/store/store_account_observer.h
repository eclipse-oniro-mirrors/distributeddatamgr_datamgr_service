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
#ifndef STORE_ACCOUNT_OBSERVER_H
#define STORE_ACCOUNT_OBSERVER_H

#include "account/account_delegate.h"
namespace OHOS {
namespace UDMF {
class RuntimeStoreAccountObserver : public DistributedData::AccountDelegate::Observer {
private:
    void OnAccountChanged(const DistributedData::AccountEventInfo &eventInfo, int32_t timeout) override;
    // must specify unique name for observer
    std::string Name() override
    {
        return "UdmfRuntimeStore";
    }
    
    LevelType GetLevel() override
    {
        return LevelType::LOW;
    }
};

} // namespace UDMF
} // namespace OHOS

#endif // STORE_ACCOUNT_OBSERVER_H