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

#include "heartbeat.h"

#include <time.h>
#include <uv.h>

#include "icmp.h"
#include "ip.h"
#include "log.h"

static void
on_req_timer(uv_timer_t* timer);

static void
on_reply_timer(uv_timer_t* timer);

static void
send_req(struct enftun_heartbeat* heartbeat);

static void
on_write(struct enftun_crb* crb)
{
    struct enftun_heartbeat* heartbeat = crb->context;

    if (crb->status)
        enftun_log_error("heartbeat: failed to send request: %d\n",
                         crb->status);

    heartbeat->req_sending = false;

    if (!heartbeat->req_inflight)
    {
        heartbeat->req_inflight = true;

        // Start timer to wait for reply
        uv_timer_start(&heartbeat->reply_timer, on_reply_timer,
                       heartbeat->reply_timeout, 0);
    }

    if (heartbeat->req_scheduled)
        send_req(heartbeat);
}

static void
send_req(struct enftun_heartbeat* heartbeat)
{
    heartbeat->req_scheduled = false;
    heartbeat->req_sending   = true;

    enftun_packet_reset(&heartbeat->req_pkt);
    enftun_icmp6_echo_request(&heartbeat->req_pkt, heartbeat->source_addr,
                              heartbeat->dest_addr);
    enftun_crb_write(&heartbeat->req_crb, heartbeat->chan);

    enftun_log_debug("heartbeat: request sent.\n");

    // Start timer again
    uv_timer_start(&heartbeat->req_timer, on_req_timer, heartbeat->req_period,
                   0);
}

static void
schedule_req(struct enftun_heartbeat* heartbeat)
{
    heartbeat->req_scheduled = true;

    if (!heartbeat->req_sending)
        send_req(heartbeat);
}

static void
on_req_timer(uv_timer_t* timer)
{
    struct enftun_heartbeat* heartbeat = timer->data;
    schedule_req(heartbeat);
}

static void
on_reply_timer(uv_timer_t* timer)
{
    struct enftun_heartbeat* heartbeat = timer->data;

    heartbeat->req_inflight = false;

    // Notify that reply timed out
    heartbeat->timeout_cb(heartbeat);

    return;
}

int
enftun_heartbeat_start(struct enftun_heartbeat* heartbeat)
{
    int rc = uv_timer_start(&heartbeat->req_timer, on_req_timer,
                            heartbeat->req_period, 0);

    return rc;
}

int
enftun_heartbeat_stop(struct enftun_heartbeat* heartbeat)
{
    uv_timer_stop(&heartbeat->req_timer);
    uv_timer_stop(&heartbeat->reply_timer);

    if (heartbeat->req_sending)
        enftun_crb_cancel(&heartbeat->req_crb);

    return 0;
}

int
enftun_heartbeat_reset(struct enftun_heartbeat* heartbeat)
{
    uv_timer_stop(&heartbeat->reply_timer);
    schedule_req(heartbeat);

    return 0;
}

int
enftun_heartbeat_now(struct enftun_heartbeat* heartbeat)
{
    schedule_req(heartbeat);
    return 0;
}

int
enftun_heartbeat_handle_packet(struct enftun_heartbeat* heartbeat,
                               struct enftun_packet* pkt)
{
    ENFTUN_SAVE_INIT(pkt);

    struct ip6_hdr* iph = enftun_ip6_pull_if_dest(pkt, heartbeat->source_addr);
    if (!iph)
        goto pass;

    struct icmp6_hdr* icmph = enftun_icmp6_echo_reply_pull(pkt, iph);
    if (!icmph)
        goto pass;

    heartbeat->req_inflight = false;
    uv_timer_stop(&heartbeat->reply_timer);

    enftun_log_debug("heartbeat: reply received.\n");

    return 1;

pass:
    ENFTUN_RESTORE(pkt);
    return 0;
}

int
enftun_heartbeat_init(struct enftun_heartbeat* heartbeat,
                      int hb_period,
                      int hb_timeout,
                      uv_loop_t* loop,
                      struct enftun_channel* chan,
                      const struct in6_addr* source,
                      const struct in6_addr* dest,
                      enftun_heartbeat_timeout cb,
                      void* data)
{
    heartbeat->chan = chan;

    heartbeat->source_addr = source;
    heartbeat->dest_addr   = dest;

    heartbeat->req_crb.context  = heartbeat;
    heartbeat->req_crb.packet   = &heartbeat->req_pkt;
    heartbeat->req_crb.complete = on_write;

    heartbeat->req_timer.data = heartbeat;
    heartbeat->req_period     = hb_period;

    heartbeat->reply_timer.data = heartbeat;
    heartbeat->reply_timeout    = hb_timeout;

    heartbeat->req_scheduled = false;
    heartbeat->req_sending   = false;
    heartbeat->req_inflight  = false;

    heartbeat->timeout_cb = cb;
    heartbeat->data       = data;

    uv_timer_init(loop, &heartbeat->req_timer);
    uv_timer_init(loop, &heartbeat->reply_timer);

    return 0;
}

int
enftun_heartbeat_free(struct enftun_heartbeat* heartbeat)
{
    (void) heartbeat;
    return 0;
}
