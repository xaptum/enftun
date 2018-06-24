/*
 * Copyright 2018 Xaptum, Inc.
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

#include "channel.h"
#include "log.h"

static
void
do_op(struct enftun_channel* chan,
      struct enftun_list* queue,
      int (*op)(void* ctx, struct enftun_packet* pkt))
{
    struct enftun_crb *crb;
    int rc;

    if (enftun_list_empty(queue))
        return;

    crb = (struct enftun_crb*) queue->next;

    rc = op(chan->ops_context, crb->packet);
    if (rc == -EAGAIN)
        return;

    enftun_list_delete(&crb->entry);
    crb->channel = NULL;

    crb->status = rc;
    crb->complete(crb);
}

static void update_poll(struct enftun_channel* chan);

static
void
on_poll(uv_poll_t* poll, int status, int events)
{
    struct enftun_channel* chan = (struct enftun_channel*) poll->data;

    if (status < 0)
        return;

    if (events & UV_READABLE)
        do_op(chan, &chan->rxqueue, chan->ops->read);

    if (events & UV_WRITABLE)
        do_op(chan, &chan->txqueue, chan->ops->write);

    update_poll(chan);
}

static
void
update_poll(struct enftun_channel* chan)
{
    if (enftun_list_empty(&chan->rxqueue))
        chan->events &= ~UV_READABLE;
    else
        chan->events |= UV_READABLE;

    if (enftun_list_empty(&chan->txqueue))
        chan->events &= ~UV_WRITABLE;
    else
        chan->events |= UV_WRITABLE;

    uv_poll_start(&chan->poll, chan->events, on_poll);
}

int
enftun_channel_init(struct enftun_channel* chan,
                    struct enftun_channel_ops* ops,
                    void* ops_context,
                    uv_loop_t* loop,
                    int fd)
{
    int rc;

    chan->ops = ops;
    chan->ops_context = ops_context;

    enftun_list_init(&chan->rxqueue);
    enftun_list_init(&chan->txqueue);

    chan->events = 0;
    chan->poll.data = chan;
    rc = uv_poll_init(loop, &chan->poll, fd);

    return rc;
}

int
enftun_channel_free(struct enftun_channel* chan)
{
    uv_poll_stop(&chan->poll);
    return 0;
}

void
enftun_crb_read(struct enftun_crb* crb, struct enftun_channel* chan)
{
    enftun_packet_reset(crb->packet);
    enftun_packet_reserve_head(crb->packet, 2); // space for stream header

    crb->channel = chan;

    enftun_list_append(&chan->rxqueue, &crb->entry);
    update_poll(chan);
}

void
enftun_crb_write(struct enftun_crb* crb, struct enftun_channel* chan)
{
    if (chan->ops->prepare)
        chan->ops->prepare(chan->ops_context, crb->packet);

    crb->channel = chan;

    enftun_list_append(&chan->txqueue, &crb->entry);
    update_poll(chan);
}

void
enftun_crb_cancel(struct enftun_crb* crb)
{
    if (!crb->channel)
        return;

    enftun_list_delete(&crb->entry);
    update_poll(crb->channel);
    crb->channel = NULL;
}
