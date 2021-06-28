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

/*
 * Periodic heartbeats to detect tunnel connection failure.
 *
 * After a period of inactivity (no packets received), send a ping
 * echo request to trigger a reply. If a packet is not received within
 * a timeout after that, consider the tunnel down.
 */

#include "heartbeat.h"

#include <time.h>
#include <uv.h>

#include "icmp6.h"
#include "ip6.h"
#include "log.h"

static void
on_request_timer(uv_timer_t* timer);

static void
on_reply_timer(uv_timer_t* timer);

static void
schedule_request(struct enftun_heartbeat* heartbeat);

static void
send_request(struct enftun_heartbeat* heartbeat);

static void
on_write(struct enftun_crb* crb)
{
    struct enftun_heartbeat* heartbeat = crb->context;

    heartbeat->request_sending = false;

    if (crb->status)
        enftun_log_error("heartbeat: failed to send request: %d\n",
                         crb->status);

    if (!heartbeat->awaiting_reply)
    {
        // Start timer to wait for reply
        uv_timer_start(&heartbeat->reply_timer, on_reply_timer,
                       heartbeat->reply_timeout, 0);

        heartbeat->awaiting_reply = true;
    }

    // If another request was scheduled, send it now.
    if (heartbeat->request_scheduled)
        send_request(heartbeat);
}

static void
send_request(struct enftun_heartbeat* heartbeat)
{
    heartbeat->request_scheduled = false;
    heartbeat->request_sending   = true;

    enftun_packet_reset(&heartbeat->request_pkt);
    enftun_icmp6_echo_request(&heartbeat->request_pkt, heartbeat->source_addr,
                              heartbeat->dest_addr);
    enftun_crb_write(&heartbeat->request_crb, heartbeat->chan);

    enftun_log_debug("heartbeat: request sent.\n");
}

static void
schedule_request(struct enftun_heartbeat* heartbeat)
{
    heartbeat->request_scheduled = true;

    if (!heartbeat->request_sending)
        send_request(heartbeat);
}

static void
on_request_timer(uv_timer_t* timer)
{
    struct enftun_heartbeat* heartbeat = timer->data;
    schedule_request(heartbeat);
}

static void
on_reply_timer(uv_timer_t* timer)
{
    struct enftun_heartbeat* heartbeat = timer->data;

    // Notify that reply timed out
    heartbeat->timeout_cb(heartbeat);
}

int
enftun_heartbeat_start(struct enftun_heartbeat* heartbeat)
{
    int rc =
        uv_timer_start(&heartbeat->request_timer, on_request_timer,
                       heartbeat->request_period, heartbeat->request_period);

    return rc;
}

int
enftun_heartbeat_stop(struct enftun_heartbeat* heartbeat)
{
    uv_timer_stop(&heartbeat->request_timer);
    uv_timer_stop(&heartbeat->reply_timer);
    heartbeat->awaiting_reply = false;

    if (heartbeat->request_sending)
        enftun_crb_cancel(&heartbeat->request_crb);

    return 0;
}

int
enftun_heartbeat_reset(struct enftun_heartbeat* heartbeat)
{
    uv_timer_again(&heartbeat->request_timer);

    uv_timer_stop(&heartbeat->reply_timer);
    heartbeat->awaiting_reply = false;

    return 0;
}

int
enftun_heartbeat_now(struct enftun_heartbeat* heartbeat)
{
    schedule_request(heartbeat);

    uv_timer_again(&heartbeat->request_timer);

    return 0;
}

int
enftun_heartbeat_handle_packet(struct enftun_heartbeat* heartbeat,
                               struct enftun_packet* pkt)
{
    ENFTUN_SAVE_INIT(pkt);

    // A packet was received, so reset the timers.
    enftun_heartbeat_reset(heartbeat);

    // If a reply to our request, steal the packet.
    struct ip6_hdr* iph = enftun_ip6_pull_if_dest(pkt, heartbeat->source_addr);
    if (!iph)
        goto pass;

    struct icmp6_hdr* icmph = enftun_icmp6_echo_reply_pull(pkt, iph);
    if (!icmph)
        goto pass;

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

    heartbeat->timeout_cb = cb;
    heartbeat->data       = data;

    heartbeat->request_period     = hb_period;
    heartbeat->request_timer.data = heartbeat;

    heartbeat->request_crb.context  = heartbeat;
    heartbeat->request_crb.packet   = &heartbeat->request_pkt;
    heartbeat->request_crb.complete = on_write;

    heartbeat->request_scheduled = false;
    heartbeat->request_sending   = false;

    heartbeat->reply_timeout    = hb_timeout;
    heartbeat->reply_timer.data = heartbeat;

    heartbeat->awaiting_reply = false;

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
