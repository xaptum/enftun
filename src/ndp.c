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

#include "ndp.h"

#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <string.h>

#include "icmp6.h"
#include "ip6.h"
#include "log.h"
#include "memory.h"
#include "packet.h"

static void
send_ra(struct enftun_ndp* ndp);

static void
schedule_ra(struct enftun_ndp* ndp);

static void
send_na(struct enftun_ndp* ndp,
        const struct in6_addr* src,
        const struct in6_addr* dst);

static void
on_timer(uv_timer_t* timer)
{
    struct enftun_ndp* ndp = timer->data;
    schedule_ra(ndp);
}

static void
on_ra_write(struct enftun_crb* crb)
{
    struct enftun_ndp* ndp = crb->context;

    if (crb->status)
        enftun_log_error("ndp: failed to send RA: %d\n", crb->status);

    ndp->ra_sending = false;
    if (ndp->ra_scheduled)
        send_ra(ndp);
}

static void
on_na_write(struct enftun_crb* crb)
{
    struct enftun_ndp* ndp = crb->context;

    if (crb->status)
        enftun_log_error("ndp: failed to send NA: %d\n", crb->status);

    ndp->na_sending = false;
}

static void
send_ra(struct enftun_ndp* ndp)
{
    ndp->ra_scheduled = false;
    ndp->ra_sending   = true;

    enftun_packet_reset(&ndp->ra_pkt);
    enftun_icmp6_nd_ra(&ndp->ra_pkt, &ip6_self, &ip6_all_nodes, &ndp->network,
                       64, ndp->routes);

    enftun_crb_write(&ndp->ra_crb, ndp->chan);

    // Start timer again
    if (ndp->ra_period > 0)
        uv_timer_start(&ndp->timer, on_timer, ndp->ra_period, 0);
}

static void
schedule_ra(struct enftun_ndp* ndp)
{
    ndp->ra_scheduled = true;

    if (!ndp->ra_sending)
        send_ra(ndp);
}

static void
send_na(struct enftun_ndp* ndp,
        const struct in6_addr* src,
        const struct in6_addr* dst)
{
    if (ndp->na_sending == true)
        return;

    ndp->na_sending = true;

    enftun_packet_reset(&ndp->na_pkt);
    enftun_icmp6_nd_na(&ndp->na_pkt, src, dst, src);

    enftun_crb_write(&ndp->na_crb, ndp->chan);
}

int
enftun_ndp_init(struct enftun_ndp* ndp,
                struct enftun_channel* chan,
                uv_loop_t* loop,
                const struct in6_addr* ipv6,
                const char** routes,
                int ra_period)
{
    int rc;

    CLEAR(*ndp);

    ndp->chan = chan;

    memcpy(&ndp->network, ipv6, 8);

    ndp->routes    = routes;
    ndp->ra_period = ra_period;

    ndp->ra_scheduled = false;
    ndp->ra_sending   = false;

    ndp->ra_crb.context  = ndp;
    ndp->ra_crb.packet   = &ndp->ra_pkt;
    ndp->ra_crb.complete = on_ra_write;

    ndp->na_sending = false;

    ndp->na_crb.context  = ndp;
    ndp->na_crb.packet   = &ndp->na_pkt;
    ndp->na_crb.complete = on_na_write;

    ndp->timer.data = ndp;
    rc              = uv_timer_init(loop, &ndp->timer);

    return rc;
}

int
enftun_ndp_free(struct enftun_ndp* ndp)
{
    CLEAR(*ndp);
    return 0;
}

int
enftun_ndp_start(struct enftun_ndp* ndp)
{
    int rc = 0;

    if (ndp->ra_period > 0)
        rc = uv_timer_start(&ndp->timer, on_timer, 0, 0);

    return rc;
}

int
enftun_ndp_stop(struct enftun_ndp* ndp)
{
    uv_timer_stop(&ndp->timer);

    if (ndp->ra_sending)
        enftun_crb_cancel(&ndp->ra_crb);

    return 0;
}

static int
handle_rs(struct enftun_ndp* ndp, struct enftun_packet* pkt)
{
    ENFTUN_SAVE_INIT(pkt);

    // Verify that this an IP packet addressed to us
    struct ip6_hdr* iph = enftun_ip6_pull_if_dest(pkt, &ip6_all_routers);
    if (!iph)
        goto pass;

    struct nd_router_solicit* rs = enftun_icmp6_nd_rs_pull(pkt, iph);
    if (!rs)
        goto pass;

    schedule_ra(ndp);
    return 1;

pass:
    ENFTUN_RESTORE(pkt);
    return 0;
}

static int
handle_ns(struct enftun_ndp* ndp, struct enftun_packet* pkt)
{
    ENFTUN_SAVE_INIT(pkt);

    struct ip6_hdr* iph = enftun_ip6_pull(pkt);
    if (!iph)
        goto pass;

    struct nd_neighbor_solicit* ns = enftun_icmp6_nd_ns_pull(pkt, iph);
    if (!ns)
        goto pass;

    send_na(ndp, &ns->nd_ns_target, &iph->ip6_src);
    return 1;

pass:
    ENFTUN_RESTORE(pkt);
    return 0;
}

int
enftun_ndp_handle_packet(struct enftun_ndp* ndp, struct enftun_packet* pkt)
{
    return handle_rs(ndp, pkt) || handle_ns(ndp, pkt);
}
