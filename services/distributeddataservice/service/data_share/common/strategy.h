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

#ifndef DATASHARESERVICE_STRAGETY_H
#define DATASHARESERVICE_STRAGETY_H

#include <list>
#include <memory>

#include "context.h"

namespace OHOS::DataShare {
class Strategy {
public:
    Strategy() = default;
    Strategy(const Strategy &) = delete;
    Strategy(const Strategy &&) = delete;
    Strategy &operator=(const Strategy &) = delete;
    Strategy &operator=(const Strategy &&) = delete;
    virtual ~Strategy()
    {
    };
    virtual bool operator()(std::shared_ptr<Context> context)
    {
        return false;
    };
};
} // namespace OHOS::DataShare
#endif // DATASHARESERVICE_STRAGETY_H
