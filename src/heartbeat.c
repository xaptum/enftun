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
on_request_timer(uv_timer_t* timer);

static void
on_reply_timer(uv_timer_t* timer);

static void
send_heartbeat(struct enftun_heartbeat* heartbeat);

static void
on_write(struct enftun_crb* crb)
{
    struct enftun_heartbeat* heartbeat = crb->context;
    if (crb->status)
        enftun_log_error("PING: failed to send heartbeat reply: %d\n",
                         crb->status);

    heartbeat->hb_sending = false;
}

static void
send_heartbeat(struct enftun_heartbeat* heartbeat)
{
    heartbeat->hb_scheduled = false;
    heartbeat->hb_sending   = true;
    heartbeat->hb_inflight  = true;

    enftun_log_debug("Ping.....");

    enftun_packet_reset(&heartbeat->reply_pkt);
    enftun_icmp6_echo_request(&heartbeat->reply_pkt, heartbeat->source_addr,
                              heartbeat->dest_addr);
    enftun_crb_write(&heartbeat->reply_crb, heartbeat->chan);

    uv_timer_start(&heartbeat->reply_timer, on_reply_timer,
                   heartbeat->heartbeat_timeout, 0);
}

static void
schedule_heartbeat(struct enftun_heartbeat* heartbeat)
{
    heartbeat->hb_scheduled = true;

    if (!heartbeat->hb_inflight && !heartbeat->hb_sending)
        send_heartbeat(heartbeat);
}

static void
on_request_timer(uv_timer_t* timer)
{
    struct enftun_heartbeat* heartbeat = timer->data;
    schedule_heartbeat(heartbeat);
}

static void
on_reply_timer(uv_timer_t* timer)
{
    struct enftun_heartbeat* heartbeat = timer->data;
    heartbeat->hb_inflight             = false;
    heartbeat->on_timeout(heartbeat->data);
    return;
}

int
enftun_heartbeat_start(struct enftun_heartbeat* heartbeat)
{
    int rc = uv_timer_start(&heartbeat->request_timer, on_request_timer,
                            heartbeat->heartbeat_period, 0);

    return rc;
}

int
enftun_heartbeat_restart(struct enftun_heartbeat* heartbeat)
{
    if (!heartbeat->hb_inflight && !heartbeat->hb_sending)
    {
        enftun_heartbeat_stop(heartbeat);
        uv_timer_start(&heartbeat->request_timer, on_request_timer,
                       heartbeat->heartbeat_period, 0);
    }

    return 0;
}

int
enftun_heartbeat_now(struct enftun_heartbeat* heartbeat)
{
    schedule_heartbeat(heartbeat);
    return 0;
}

int
enftun_heartbeat_stop(struct enftun_heartbeat* heartbeat)
{
    uv_timer_stop(&heartbeat->request_timer);
    uv_timer_stop(&heartbeat->reply_timer);

    if (heartbeat->hb_sending)
        enftun_crb_cancel(&heartbeat->reply_crb);

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

    heartbeat->hb_inflight = false;

    enftun_log_debug("Received ping reply\n");

    if (heartbeat->hb_scheduled)
    {
        enftun_heartbeat_stop(heartbeat);
        send_heartbeat(heartbeat);
    }
    else
        enftun_heartbeat_restart(heartbeat);

    return 0;

pass:
    ENFTUN_RESTORE(pkt);
    return 1;
}

int
enftun_heartbeat_init(struct enftun_heartbeat* heartbeat,
                      uv_loop_t* loop,
                      struct enftun_channel* chan,
                      const struct in6_addr* source,
                      const struct in6_addr* dest,
                      void (*on_timeout)(void* data),
                      void* cb_ctx,
                      int hb_period,
                      int hb_timeout)
{
    heartbeat->chan = chan;

    heartbeat->source_addr = source;
    heartbeat->dest_addr   = dest;

    heartbeat->reply_crb.context  = heartbeat;
    heartbeat->reply_crb.packet   = &heartbeat->reply_pkt;
    heartbeat->reply_crb.complete = on_write;

    heartbeat->request_timer.data = heartbeat;
    heartbeat->heartbeat_period   = hb_period;

    heartbeat->reply_timer.data  = heartbeat;
    heartbeat->heartbeat_timeout = hb_timeout;

    heartbeat->hb_scheduled = false;
    heartbeat->hb_sending   = false;
    heartbeat->hb_inflight  = false;

    heartbeat->on_timeout = on_timeout;
    heartbeat->data       = cb_ctx;

    uv_timer_init(loop, &heartbeat->request_timer);
    uv_timer_init(loop, &heartbeat->reply_timer);

    return 0;
}

int
enftun_heartbeat_free(struct enftun_heartbeat* heartbeat)
{
    (void) heartbeat;
    return 0;
}
