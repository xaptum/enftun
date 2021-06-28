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

#include "dhcp.h"

#include <string.h>

#include <netinet/ip6.h>
#include <netinet/udp.h>

#include "dhcp6_msgs.h"
#include "dhcp6_types.h"
#include "ip6.h"
#include "log.h"
#include "memory.h"
#include "packet.h"

static void
on_write(struct enftun_crb* crb)
{
    struct enftun_dhcp* dhcp = crb->context;

    if (crb->status)
        enftun_log_error("dhcp: failed to send packet: %d\n", crb->status);

    dhcp->inflight = false;
}

static int
prep_message(struct enftun_dhcp* dhcp)
{
    if (dhcp->inflight)
        return -1;

    enftun_packet_reset(&dhcp->pkt);
    enftun_udp6_reserve(&dhcp->pkt);

    return 0;
}

static int
send_message(struct enftun_dhcp* dhcp, const struct in6_addr* dst)
{
    if (!enftun_udp6_header(&dhcp->pkt, 255, &ip6_self, dst, 547, 546))
        return -1;

    dhcp->inflight = true;
    enftun_crb_write(&dhcp->crb, dhcp->chan);

    return 0;
}

static void
send_advertise(struct enftun_dhcp* dhcp, struct enftun_dhcp6_context* ctx)
{
    ctx->sid    = dhcp->duid;
    ctx->sidlen = sizeof(dhcp->duid);

    if (prep_message(dhcp))
        return;

    if (!enftun_dhcp6_advertise(&dhcp->pkt, ctx, &dhcp->ipv6))
        return;

    send_message(dhcp, ctx->lladdr);
}

static void
send_reply(struct enftun_dhcp* dhcp, struct enftun_dhcp6_context* ctx)
{
    ctx->sid    = dhcp->duid;
    ctx->sidlen = sizeof(dhcp->duid);

    if (prep_message(dhcp))
        return;

    if (!enftun_dhcp6_reply(&dhcp->pkt, ctx, &dhcp->ipv6))
        return;

    send_message(dhcp, ctx->lladdr);
}

static bool
handle_solicit(struct enftun_dhcp* dhcp, struct enftun_dhcp6_context* ctx)
{
    send_advertise(dhcp, ctx);
    return true;
}

static bool
handle_request(struct enftun_dhcp* dhcp, struct enftun_dhcp6_context* ctx)
{
    if (!ctx->iaid)
        return false;

    if (ctx->sidlen != sizeof(dhcp->duid))
        return false;

    if (0 != memcmp(ctx->sid, dhcp->duid, sizeof(dhcp->duid)))
        return false;

    send_reply(dhcp, ctx);
    return true;
}

static bool
handle_confirm(struct enftun_dhcp* dhcp, struct enftun_dhcp6_context* ctx)
{
    if (!ctx->iaid)
        return false;

    if (ctx->sidlen != sizeof(dhcp->duid))
        return false;

    if (0 != memcmp(ctx->sid, dhcp->duid, sizeof(dhcp->duid)))
        return false;

    send_reply(dhcp, ctx);
    return true;
}

int
enftun_dhcp_init(struct enftun_dhcp* dhcp,
                 struct enftun_channel* chan,
                 const struct in6_addr* ipv6)
{
    int rc = 0;

    CLEAR(*dhcp);

    dhcp->chan = chan;

    dhcp->inflight = false;

    dhcp->crb.context  = dhcp;
    dhcp->crb.packet   = &dhcp->pkt;
    dhcp->crb.complete = on_write;

    uint8_t default_duid[18] = {0x00, 0x04, 0x01, 0x02, 0x03, 0x04,
                                0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
                                0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    memcpy(dhcp->duid, default_duid, sizeof(dhcp->duid));
    memcpy(&dhcp->ipv6, ipv6, sizeof(dhcp->ipv6));

    return rc;
}

int
enftun_dhcp_free(struct enftun_dhcp* dhcp)
{
    CLEAR(*dhcp);
    return 0;
}

int
enftun_dhcp_handle_packet(struct enftun_dhcp* dhcp, struct enftun_packet* pkt)
{
    ENFTUN_SAVE_INIT(pkt);

    struct enftun_dhcp6_context ctx;
    CLEAR(ctx);

    // Verify that this an UDP packet addressed to us
    struct ip6_hdr* iph = enftun_udp6_pull_if_dest(
        pkt, &ip6_all_dhcp_relay_agents_and_servers, 0, 547);
    if (!iph)
        goto pass;

    ctx.lladdr = &iph->ip6_src;

    struct dhcp6_msg* msg = enftun_dhcp6_parse(pkt, &ctx);
    if (!msg)
        goto pass;

    switch (msg->type)
    {
    case DHCP6_SOLICIT:
        handle_solicit(dhcp, &ctx);
        break;
    case DHCP6_REQUEST:
        handle_request(dhcp, &ctx);
        break;
    case DHCP6_CONFIRM:
        handle_confirm(dhcp, &ctx);
        break;
    default:
        break; // Drop all other types
    }

    return 1;

pass:
    ENFTUN_RESTORE(pkt);
    return 0;
}
