/*
 * Copyright 2021 Xaptum, Inc.
 *
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

#include "nat.h"

#include <stdlib.h>

#include "ip6.h"
#include "log.h"
#include "memory.h"
#include "packet.h"

int
enftun_nat_init(struct enftun_nat* nat,
                struct enftun_nat_rule* rules,
                size_t len,
                const struct in6_addr* self)
{
    CLEAR(*nat);

    nat->rules_len     = len;
    nat->rules_forward = rules;
    nat->rules_reverse = calloc(len, sizeof(struct enftun_nat_rule));

    nat->self = self;

    for (size_t i = 0; i < nat->rules_len; ++i)
    {
        if (enftun_nat_rule_normalize(nat->rules_forward + i, nat->self) != 0)
        {
            enftun_log_error("Invalid NAT rule %i\n", i);
            return -1;
        }
        enftun_nat_rule_reverse(nat->rules_forward + i, nat->rules_reverse + i);
    }

    return 0;
}

int
enftun_nat_free(struct enftun_nat* nat)
{
    free(nat->rules_reverse);
    return 0;
}

static int
apply_rules(struct enftun_nat* nat, struct enftun_packet* pkt)
{
    ENFTUN_SAVE_INIT(pkt);

    struct ip6_hdr* iph = enftun_ip6_pull(pkt);
    if (!iph)
        return 0;

    for (size_t i = 0; i < nat->rules_len; ++i)
    {
        if (enftun_nat_rule_apply(nat->rules_forward + i, iph, pkt->data,
                                  pkt->size) == 0)
            break;
    }

    for (size_t i = 0; i < nat->rules_len; ++i)
    {
        if (enftun_nat_rule_apply(nat->rules_reverse + i, iph, pkt->data,
                                  pkt->size) == 0)
            break;
    }

    ENFTUN_RESTORE(pkt);

    return 0;
}

int
enftun_nat_ingress(struct enftun_nat* nat, struct enftun_packet* pkt)
{
    return apply_rules(nat, pkt);
}

int
enftun_nat_egress(struct enftun_nat* nat, struct enftun_packet* pkt)
{
    return apply_rules(nat, pkt);
}
