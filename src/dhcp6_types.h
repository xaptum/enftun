/*
 * Copyright 2019 Xaptum, Inc.
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

#pragma once

#ifndef ENFTUN_DHCP6_TYPES_H
#define ENFTUN_DHCP6_TYPES_H

#include <netinet/in.h>

#define DHCP6_SOLICIT       1
#define DHCP6_ADVERTISE     2
#define DHCP6_REQUEST       3
#define DHCP6_CONFIRM       4
#define DHCP6_RENEW         5
#define DHCP6_REBIND        6
#define DHCP6_REPLY         7
#define DHCP6_RELEASE       8
#define DHCP6_DECLINE       9
#define DHCP6_RECONFIGURE  10
#define DHCP6_INFO_REQUEST 11
#define DHCP6_RELAY_FORW   12
#define DHCP6_RELAY_REPL   13

struct dhcp6_msg {
    uint8_t type;
    uint8_t xid[3];
    // options are here
};

struct dhcp6_relay_msg {
    uint8_t type;
    uint8_t hops;
    uint8_t linkaddr[16];
    uint8_t peeraddr[16];
    // options are here
};

#define DHCP6_OPTION_CLIENTID           1
#define DHCP6_OPTION_SERVERID           2
#define DHCP6_OPTION_IA_NA              3
#define DHCP6_OPTION_IA_TA              4
#define DHCP6_OPTION_IAADDR             5
#define DHCP6_OPTION_ORO                6
#define DHCP6_OPTION_PREFERENCE         7
#define DHCP6_OPTION_ELAPSED_TIME       8
#define DHCP6_OPTION_RELAY_MSG          9
#define DHCP6_OPTION_AUTH              11
#define DHCP6_OPTION_UNICAST           12
#define DHCP6_OPTION_STATUS_CODE       13
#define DHCP6_OPTION_RAPID_COMMIT      14
#define DHCP6_OPTION_USER_CLASS        15
#define DHCP6_OPTION_VENDOR_CLASS      16
#define DHCP6_OPTION_VENDOR_OPTS       17
#define DHCP6_OPTION_INTERFACE_ID      18
#define DHCP6_OPTION_RECONF_MSG        19
#define DHCP6_OPTION_RECONF_ACCEPT     20
#define DHCP6_OPTION_DNS_SERVERS       23
#define DHCP6_OPTION_DOMAIN_LIST       24
#define DHCP6_OPTION_IA_PD             25
#define DHCP6_OPTION_IAPREFIX          26
#define DHCP6_OPTION_INFO_REFRESH_TIME 32
#define DHCP6_OPTION_SOL_MAX_RT        82
#define DHCP6_OPTION_INF_MAX_RT        83

struct dhcp6_option {
    uint16_t code;
    uint16_t len;
    // data is here
};

struct dhcp6_ia_na {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    // IA_NA options are here
};

struct dhcp6_ia_ta {
    uint32_t iaid;
    // IA_TA options are here
};

struct dhcp6_iaaddr {
    struct in6_addr addr;
    uint32_t pltime; // preferred lifetime
    uint32_t vltime; // valid lifetime
    // IAAddr options are here
};

struct dchp6_preference {
    uint8_t pref;
};

struct dhcp6_elapsed_time {
    uint16_t elapsed;
};

struct dhcp6_auth {
    uint8_t proto;
    uint8_t alg;
    uint8_t rdm;
    uint8_t replay[8];
    // authentication information here (variable length)
};

struct dhcp6_unicast {
    struct in6_addr saddr;
};

struct dchp6_status_code {
    uint16_t code;
    // message (variable length)
};

struct dchp6_vendor_class {
    uint32_t enterprise_num;
    // vendor class data (variable length)
};

struct dchp6_vendor_opts {
    uint32_t enterprise_num;
    // vendor option data (variable length)
};

struct dchp6_reconf_msg {
    uint8_t type;
};

struct dhcp6_ia_pd {
    uint32_t iaid;
    uint32_t t1;
    uint32_t t2;
    // IA_PD options are here
};

struct dhcp6_iaprefix {
    uint32_t pltime;    // preferred lifetime
    uint32_t vltime;    // valid lifetime
    uint8_t  prefixlen;
    struct in6_addr prefix;
    // IAPrefix options are here
};

struct dhcp6_info_refresh_time {
    uint32_t time;
};

struct dchp6_sol_max_rt {
    uint32_t sol_max_rt;
};

struct dchp6_inf_max_rt {
    uint32_t inf_max_rt;
};

#endif // ENFTUN_DHCP6_TYPES_H
