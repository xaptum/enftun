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

#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <string.h>

#include "ip.h"
#include "icmp.h"
#include "log.h"
#include "packet.h"

static void send_ra(struct enftun_ndp* ndp);
static void schedule_ra(struct enftun_ndp* ndp);

static
void
on_timer(uv_timer_t* timer)
{
    struct enftun_ndp* ndp = timer->data;
    schedule_ra(ndp);
}

static
void
on_write(struct enftun_crb* crb)
{
    struct enftun_ndp* ndp = crb->context;

    if (crb->status)
        enftun_log_error("ndp: failed to send RA: %d\n", crb->status);

    ndp->ra_inflight = false;
    if (ndp->ra_scheduled)
        send_ra(ndp);
}

static
void
send_ra(struct enftun_ndp* ndp)
{
    ndp->ra_scheduled = false;
    ndp->ra_inflight = true;

    enftun_packet_reset(&ndp->ra_pkt);
    icmp6_make_nd_ra(&ndp->ra_pkt, &ip6_self, &ip6_all_nodes,
                     ndp->routes, 3 * ndp->ra_period);

    enftun_crb_write(&ndp->ra_crb, ndp->chan);

    // Start timer again
    uv_timer_start(&ndp->timer, on_timer, ndp->ra_period, 0);
}

static
void
schedule_ra(struct enftun_ndp* ndp)
{
    ndp->ra_scheduled = true;

    if (!ndp->ra_inflight)
        send_ra(ndp);
}

int
enftun_ndp_init(struct enftun_ndp* ndp,
                struct enftun_channel* chan,
                uv_loop_t* loop,
                const char** routes,
                int ra_period)
{
    int rc;

    ndp->chan = chan;
    ndp->routes = routes;
    ndp->ra_period = ra_period;

    ndp->ra_scheduled = false;
    ndp->ra_inflight = false;

    ndp->ra_crb.context = ndp;
    ndp->ra_crb.packet = &ndp->ra_pkt;
    ndp->ra_crb.complete = on_write;

    ndp->timer.data = ndp;
    rc = uv_timer_init(loop, &ndp->timer);

    return rc;
}

int
enftun_ndp_free(struct enftun_ndp* ndp)
{
    (void) ndp;

    return 0;
}

int
enftun_ndp_start(struct enftun_ndp* ndp)
{
    int rc;

    rc = uv_timer_start(&ndp->timer, on_timer, 0, 0);

    return rc;
}

int
enftun_ndp_stop(struct enftun_ndp* ndp)
{
    uv_timer_stop(&ndp->timer);

    return 0;
}

int
enftun_ndp_handle_rs(struct enftun_ndp* ndp, struct enftun_packet* pkt)
{
    if (icmp6_is_nd_rs(pkt)) {
        schedule_ra(ndp);
        return 1;
    }

    return 0;
}
