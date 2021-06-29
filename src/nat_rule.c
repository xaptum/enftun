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

#include "nat_rule.h"

#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "memory.h"

/*
 * Validates and normalizes a rule.
 *
 * - Expands a rule by filling any missing values on the RHS that can
 * be inferred from the LHS.  E.g., a rule that leaves the dst port
 * unchanged is expanded from (..., 443) -> (..., _) to (..., 443) ->
 * (..., 443).
 *
 * - Checks the reverse of the rule is static. E.g., a rule that tries
 *   to change any dst port to fixed value (..., _) -> (..., 443) is
 *   rejected because the reverse rule is not static. It requires
 *   remembering the original dst port.
 */
#define IS_ANY(value) memeqzero(&value, sizeof(value))

#define IS_SELF(value) memeq(&value, sizeof(value), 0xff)

#define CHECK_TRANSLATION(lhs, rhs)                                            \
    if (IS_ANY(lhs) && !IS_ANY(rhs))                                           \
    return -1

#define EXPAND_TRANSLATION(lhs, rhs)                                           \
    if (!IS_ANY(lhs) && IS_ANY(rhs))                                           \
    rhs = lhs

#define NORMALIZE_TRANSLATION(lhs, rhs)                                        \
    CHECK_TRANSLATION(lhs, rhs);                                               \
    EXPAND_TRANSLATION(lhs, rhs)

#define REPLACE_SELF(addr, self)                                               \
    if (IS_SELF(addr))                                                         \
    addr = *self

int
enftun_nat_rule_normalize(struct enftun_nat_rule* rule,
                          const struct in6_addr* self)
{
    REPLACE_SELF(rule->match.src.addr, self);
    REPLACE_SELF(rule->match.dst.addr, self);
    REPLACE_SELF(rule->trans.src.addr, self);
    REPLACE_SELF(rule->trans.dst.addr, self);

    NORMALIZE_TRANSLATION(rule->match.src.addr, rule->trans.src.addr);
    NORMALIZE_TRANSLATION(rule->match.src.port, rule->trans.src.port);
    NORMALIZE_TRANSLATION(rule->match.dst.addr, rule->trans.dst.addr);
    NORMALIZE_TRANSLATION(rule->match.dst.port, rule->trans.dst.port);
    return 0;
}

void
enftun_nat_rule_reverse(const struct enftun_nat_rule* rule,
                        struct enftun_nat_rule* reversed)
{
    reversed->proto = rule->proto;

    reversed->match.src = rule->trans.dst;
    reversed->match.dst = rule->trans.src;

    reversed->trans.src = rule->match.dst;
    reversed->trans.dst = rule->match.src;
}

#define MATCHES(lhs, rhs)                                                      \
    (IS_ANY(lhs) || (memcmp(&lhs, &rhs, sizeof(rhs)) == 0))

bool
match_packet(const struct enftun_nat_rule* rule,
             struct ip6_hdr* nh,
             void* payload,
             size_t payload_len)
{
    struct udphdr* uh;
    struct tcphdr* th;

    if (!MATCHES(rule->proto, nh->ip6_nxt))
        return 0;

    if (!MATCHES(rule->match.src.addr, nh->ip6_src) ||
        !MATCHES(rule->match.dst.addr, nh->ip6_dst))
        return 0;

    switch (nh->ip6_nxt)
    {
    case IPPROTO_UDP:
        if (payload_len < sizeof(struct udphdr))
            return 0;

        uh = payload;
        return MATCHES(rule->match.src.port, uh->uh_sport) &&
               MATCHES(rule->match.dst.port, uh->uh_dport);
    case IPPROTO_TCP:
        if (payload_len < sizeof(struct tcphdr))
            return 0;

        th = payload;
        return MATCHES(rule->match.src.port, th->th_sport) &&
               MATCHES(rule->match.dst.port, th->th_dport);
    default:
        return 0;
    }
}

#define TRANSLATE(lhs, rhs)                                                    \
    if (!IS_ANY(lhs))                                                          \
    rhs = lhs

void
translate_packet(const struct enftun_nat_rule* rule,
                 struct ip6_hdr* nh,
                 void* payload)
{
    struct udphdr* uh;
    struct tcphdr* th;

    TRANSLATE(rule->trans.src.addr, nh->ip6_src);
    TRANSLATE(rule->trans.dst.addr, nh->ip6_dst);

    switch (nh->ip6_nxt)
    {
    case IPPROTO_UDP:
        uh = payload;

        TRANSLATE(rule->trans.src.port, uh->uh_sport);
        TRANSLATE(rule->trans.dst.port, uh->uh_dport);

        uh->uh_sum = 0;
        uh->uh_sum = ip6_l3_cksum(nh, uh);
        break;
    case IPPROTO_TCP:
        th = payload;

        TRANSLATE(rule->trans.src.port, th->th_sport);
        TRANSLATE(rule->trans.dst.port, th->th_dport);

        th->th_sum = 0;
        th->th_sum = ip6_l3_cksum(nh, th);
        break;
    }
}

int
enftun_nat_rule_apply(const struct enftun_nat_rule* rule,
                      struct ip6_hdr* nh,
                      void* payload,
                      size_t payload_len)
{
    if (match_packet(rule, nh, payload, payload_len))
    {
        translate_packet(rule, nh, payload);
        return 0;
    }

    return -1;
}
