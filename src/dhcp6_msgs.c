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

#include "dhcp6_msgs.h"

#include <stdbool.h>
#include <string.h>

#define DHCP6_ONE_YEAR 31536000

static void*
dhcp6_find_option(struct enftun_packet* pkt, uint16_t code, uint16_t* len)
{
    ENFTUN_SAVE_INIT(pkt);
    void* ret = NULL;

    for (;;)
    {
        struct dhcp6_option* opt = enftun_packet_remove_head(pkt, sizeof(*opt));
        if (!opt)
            break;

        void* body = enftun_packet_remove_head(pkt, ntohs(opt->len));
        if (!body)
            break;

        if (code != ntohs(opt->code))
            continue;

        *len = ntohs(opt->len);
        ret  = body;
        break;
    }

    ENFTUN_RESTORE(pkt);
    return ret;
}

static bool
dhcp6_find_cid(struct enftun_packet* pkt, struct enftun_dhcp6_context* ctx)
{
    uint8_t* cid = dhcp6_find_option(pkt, DHCP6_OPTION_CLIENTID, &ctx->cidlen);
    if (!cid)
        return false;

    ctx->cid = cid;
    return true;
}

static bool
dhcp6_find_sid(struct enftun_packet* pkt, struct enftun_dhcp6_context* ctx)
{
    uint8_t* sid = dhcp6_find_option(pkt, DHCP6_OPTION_SERVERID, &ctx->sidlen);
    if (!sid)
        return false;

    ctx->sid = sid;
    return true;
}

static bool
dhcp6_find_ia_na(struct enftun_packet* pkt, struct enftun_dhcp6_context* ctx)
{
    uint16_t ia_len;
    struct dhcp6_ia_na* ia =
        dhcp6_find_option(pkt, DHCP6_OPTION_IA_NA, &ia_len);
    if (!ia)
        return false;

    ctx->iaid = ntohl(ia->iaid);
    return true;
}

struct dhcp6_msg*
enftun_dhcp6_parse(struct enftun_packet* pkt, struct enftun_dhcp6_context* ctx)
{
    ENFTUN_SAVE_INIT(pkt);

    struct dhcp6_msg* msg = enftun_packet_remove_head(pkt, sizeof(*msg));
    if (!msg)
        goto err;

    ctx->xid = msg->xid;

    // Parse all the required options
    if (!dhcp6_find_cid(pkt, ctx))
        goto err;

    // Parse all the optional options that we might care about
    dhcp6_find_sid(pkt, ctx);
    dhcp6_find_ia_na(pkt, ctx);

    goto out;

err:
    msg = NULL;

out:
    ENFTUN_RESTORE(pkt);
    return msg;
}

struct dhcp6_msg*
enftun_dhcp6_advertise(struct enftun_packet* pkt,
                       struct enftun_dhcp6_context* ctx,
                       const struct in6_addr* caddr)
{
    struct dhcp6_msg* msg = enftun_dhcp6_msg(pkt, DHCP6_ADVERTISE, ctx->xid);
    if (!msg)
        return NULL;
    if (!enftun_dhcp6_clientid(pkt, ctx->cid, ctx->cidlen))
        return NULL;
    if (!enftun_dhcp6_serverid(pkt, ctx->sid, ctx->sidlen))
        return NULL;

    if (ctx->iaid && caddr)
    {
        // Set T1 and T2 to .5 and .8 times preferred lifetime, per RFC 3315
        // Section 22.4
        struct dhcp6_option* ia_na = enftun_dhcp6_ia_na_start(
            pkt, ctx->iaid, 0.5 * DHCP6_ONE_YEAR, 0.8 * DHCP6_ONE_YEAR);
        if (!ia_na)
            return NULL;

        struct dhcp6_option* iaaddr = enftun_dhcp6_iaaddr_start(
            pkt, caddr, DHCP6_ONE_YEAR, DHCP6_ONE_YEAR);
        if (!iaaddr)
            return NULL;

        enftun_dhcp6_iaaddr_finish(pkt, iaaddr);
        enftun_dhcp6_ia_na_finish(pkt, ia_na);
    }

    // Connman had a bug that prevented it from parsing the last
    // option in a message. It was fixed in 1.14, but we include a
    // workaround to support old gateways: include an optional
    // status_code option as the last message.
    if (!enftun_dhcp6_status_code(pkt, DHCP6_STATUS_CODE_SUCCESS))
        return NULL;

    return msg;
}

struct dhcp6_msg*
enftun_dhcp6_reply(struct enftun_packet* pkt,
                   struct enftun_dhcp6_context* ctx,
                   const struct in6_addr* caddr)
{
    struct dhcp6_msg* msg = enftun_dhcp6_msg(pkt, DHCP6_REPLY, ctx->xid);

    if (!msg)
        return NULL;
    if (!enftun_dhcp6_clientid(pkt, ctx->cid, ctx->cidlen))
        return NULL;
    if (!enftun_dhcp6_serverid(pkt, ctx->sid, ctx->sidlen))
        return NULL;

    // Set T1 and T2 to .5 and .8 times preferred lifetime, per RFC 3315
    // Section 22.4
    struct dhcp6_option* ia_na = enftun_dhcp6_ia_na_start(
        pkt, ctx->iaid, 0.5 * DHCP6_ONE_YEAR, 0.8 * DHCP6_ONE_YEAR);
    if (!ia_na)
        return NULL;

    struct dhcp6_option* iaaddr =
        enftun_dhcp6_iaaddr_start(pkt, caddr, DHCP6_ONE_YEAR, DHCP6_ONE_YEAR);
    if (!iaaddr)
        return NULL;
    enftun_dhcp6_iaaddr_finish(pkt, iaaddr);
    enftun_dhcp6_ia_na_finish(pkt, ia_na);

    // Connman had a bug that prevented it from parsing the last
    // option in a message. It was fixed in 1.14, but we include a
    // workaround to support old gateways: include an optional
    // status_code option as the last message.
    if (!enftun_dhcp6_status_code(pkt, DHCP6_STATUS_CODE_SUCCESS))
        return NULL;

    return msg;
}

struct dhcp6_msg*
enftun_dhcp6_msg(struct enftun_packet* pkt, uint8_t type, const uint8_t* xid)
{
    struct dhcp6_msg* msg = enftun_packet_insert_tail(pkt, sizeof(*msg));
    if (!msg)
        return NULL;

    msg->type = type;
    memcpy(&msg->xid, xid, 3);

    return msg;
}

#define DHCP6_INIT_OPT(opt_code)                                               \
    struct dhcp6_option* opt = enftun_packet_insert_tail(pkt, sizeof(*opt));   \
    if (!opt)                                                                  \
        return NULL;                                                           \
                                                                               \
    opt->code = htons(opt_code);                                               \
    opt->len  = htons(0)

#define DHCP6_INIT_OPT_BODY(opt_code, body_type)                               \
    DHCP6_INIT_OPT(opt_code);                                                  \
                                                                               \
    body_type* body = enftun_packet_insert_tail(pkt, sizeof(*body));           \
    if (!body)                                                                 \
        return NULL;                                                           \
                                                                               \
    opt->len = htons(sizeof(*body))

#define DHCP6_INIT_OPT_BODY_SIZE(opt_code, body_size)                          \
    DHCP6_INIT_OPT(opt_code);                                                  \
                                                                               \
    void* body = enftun_packet_insert_tail(pkt, body_size);                    \
    if (!body)                                                                 \
        return NULL;                                                           \
                                                                               \
    opt->len = htons(body_size)

struct dhcp6_option*
enftun_dhcp6_clientid(struct enftun_packet* pkt,
                      const uint8_t* duid,
                      size_t duidlen)
{
    DHCP6_INIT_OPT_BODY_SIZE(DHCP6_OPTION_CLIENTID, duidlen);
    memcpy(body, duid, duidlen);
    return opt;
}

struct dhcp6_option*
enftun_dhcp6_serverid(struct enftun_packet* pkt,
                      const uint8_t* duid,
                      size_t duidlen)
{
    DHCP6_INIT_OPT_BODY_SIZE(DHCP6_OPTION_SERVERID, duidlen);
    memcpy(body, duid, duidlen);
    return opt;
}

struct dhcp6_option*
enftun_dhcp6_ia_na_start(struct enftun_packet* pkt,
                         uint32_t iaid,
                         uint32_t t1,
                         uint32_t t2)
{
    DHCP6_INIT_OPT_BODY(DHCP6_OPTION_IA_NA, struct dhcp6_ia_na);
    body->iaid = htonl(iaid);
    body->t1   = htonl(t1);
    body->t2   = htonl(t2);
    return opt;
}

struct dhcp6_option*
enftun_dhcp6_iaaddr_start(struct enftun_packet* pkt,
                          const struct in6_addr* addr,
                          uint32_t pltime,
                          uint32_t vltime)
{
    DHCP6_INIT_OPT_BODY(DHCP6_OPTION_IAADDR, struct dhcp6_iaaddr);
    memcpy(&body->addr, addr, sizeof(body->addr));
    body->pltime = htonl(pltime);
    body->vltime = htonl(vltime);
    return opt;
}

struct dhcp6_option*
enftun_dhcp6_status_code(struct enftun_packet* pkt, uint16_t code)
{
    DHCP6_INIT_OPT_BODY(DHCP6_OPTION_STATUS_CODE, struct dhcp6_status_code);
    body->code = htons(code);
    return opt;
}
