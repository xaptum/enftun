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

#include <stdlib.h>

#include <arpa/inet.h>
#include <libconfig.h>

#include "log.h"
#include "memory.h"
#include "nat_rule.h"

static int
parse_proto(const char* src, uint8_t* proto)
{
    if (strcmp(src, "") == 0)
        *proto = 0;
    else if (strcmp(src, "tcp") == 0)
        *proto = IPPROTO_TCP;
    else if (strcmp(src, "TCP") == 0)
        *proto = IPPROTO_TCP;
    else if (strcmp(src, "udp") == 0)
        *proto = IPPROTO_UDP;
    else if (strcmp(src, "UDP") == 0)
        *proto = IPPROTO_UDP;
    else
        return -1;

    return 0;
}

static int
parse_port(const char* src, uint16_t* port)
{
    *port = htons(atoi(src)); // TODO: silently ignores errors, so should
                              // switch to a strtonum-like function.
    return 0;
}

static int
parse_addr(const char* src, struct in6_addr* addr)
{
    struct in_addr addr4;
    CLEAR(*addr);

    if (strcmp(src, "") == 0)
        return 0;

    if (strcmp(src, "self") == 0)
    {
        memset(&addr->s6_addr, 0xff, 16);
        return 0;
    }

    if (inet_pton(AF_INET6, src, addr) == 1)
        return 0;

    if (inet_pton(AF_INET, src, &addr4) == 1)
    {
        addr->s6_addr[10] = 0xff;
        addr->s6_addr[11] = 0xff;
        memcpy(&addr->s6_addr[12], &addr4, 4);
        return 0;
    }

    return -1;
}

/**
 * Looks up the value of NAT rule list in the configuration config
 * specified by the path path. It stores the values in a
 * null-terminated array at value.
 */
#define PARSE_FIELD(field, s, path, parser)                                    \
    const char* path = NULL;                                                   \
    if (config_setting_lookup_string(s, #path, &path))                         \
        if (parser(path, &field) < 0)                                          \
            return -1;

#define PARSE_PROTO(field, s, path) PARSE_FIELD(field, s, path, parse_proto)

#define PARSE_PORT(field, s, path) PARSE_FIELD(field, s, path, parse_port)

#define PARSE_ADDR(field, s, path) PARSE_FIELD(field, s, path, parse_addr)

static int
lookup_nat_rule(config_setting_t* g, struct enftun_nat_rule* rule)
{
    if (!config_setting_is_group(g))
        return -1;

    PARSE_PROTO(rule->proto, g, proto);
    PARSE_ADDR(rule->match.src.addr, g, src_addr);
    PARSE_PORT(rule->match.src.port, g, src_port);
    PARSE_ADDR(rule->match.dst.addr, g, dst_addr);
    PARSE_PORT(rule->match.dst.port, g, dst_port);
    PARSE_ADDR(rule->trans.src.addr, g, trans_src_addr);
    PARSE_PORT(rule->trans.src.port, g, trans_src_port);
    PARSE_ADDR(rule->trans.dst.addr, g, trans_dst_addr);
    PARSE_PORT(rule->trans.dst.port, g, trans_dst_port);

    return 0;
}

/**
 * Looks up the value of NAT rule list in the configuration config
 * specified by the path path. It stores the values in a
 * null-terminated array at value.
 *
 * The caller is responsible for free-ing value.  If value was
 * non-NULL when called, this method will free it.
 */
void
lookup_nat_rule_list(config_t* cfg,
                     const char* path,
                     struct enftun_nat_rule** value,
                     size_t* len)
{
    config_setting_t* s = config_lookup(cfg, path);
    if (!s || !config_setting_is_list(s))
        return;

    int cnt = config_setting_length(s);
    if (*value)
        free(*value);
    *value = calloc(cnt, sizeof(struct enftun_nat_rule));
    *len   = cnt;
    for (int i = 0; i < cnt; i++)
    {
        if (lookup_nat_rule(config_setting_get_elem(s, i), &(*value)[i]) < 0)
            enftun_log_error("Invalid NAT rule in config\n");
    }
}
