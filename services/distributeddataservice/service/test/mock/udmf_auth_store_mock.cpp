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

#include "udmf_auth_store_mock.h"

#include "store_cache.h"
namespace OHOS::UDMF {
std::shared_ptr<Store> AuthStoreRegistry::current;
StoreCache &StoreCache::GetInstance()
{
    static StoreCache instance;
    return instance;
}
std::shared_ptr<Store> StoreCache::GetStore(const std::string &intention)
{
    return intention == "drag" ? AuthStoreRegistry::current : nullptr;
}
void StoreCache::SetThreadPool(std::shared_ptr<ExecutorPool>)
{
}
void StoreCache::RemoveStore(const std::string &)
{
}
void StoreCache::CloseStores()
{
    AuthStoreRegistry::current.reset();
}
} // namespace OHOS::UDMF
