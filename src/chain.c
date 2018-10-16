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

#include <arpa/inet.h>

#include "chain.h"
#include "log.h"

static
void
on_complete(struct enftun_crb* crb)
{
    struct enftun_chain* chain = (struct enftun_chain*) crb->context;
    int handled;

    if (crb->status < 0)
    {
        chain->complete(chain, crb->status);
        return;
    }

    switch (chain->state)
    {
    case enftun_chain_reading:
        handled = chain->filter(chain, &chain->packet);
        if (!handled)
        {
            chain->state = enftun_chain_writing;
            enftun_crb_write(&chain->crb, chain->output);
        }
        break;
    case enftun_chain_writing:
        chain->state = enftun_chain_reading;
        enftun_crb_read(&chain->crb, chain->input);
        break;
    }
}

int
enftun_chain_init(struct enftun_chain* chain,
                  struct enftun_channel* input,
                  struct enftun_channel* output,
                  void* data,
                  enftun_chain_filter filter)
{
    chain->input = input;
    chain->output = output;

    chain->crb.packet   = &chain->packet;
    chain->crb.context  = chain;
    chain->crb.complete = on_complete;

    chain->data = data;
    chain->filter = filter;

    return 0;
}

int
enftun_chain_free(struct enftun_chain* chain __attribute__((unused)))
{
    return 0;
}

int
enftun_chain_start(struct enftun_chain* chain,
                   enftun_chain_complete complete)
{
    chain->complete = complete;
    chain->state = enftun_chain_reading;
    enftun_crb_read(&chain->crb, chain->input);
    return 0;
}

int
enftun_chain_stop(struct enftun_chain* chain)
{
    enftun_crb_cancel(&chain->crb);
    return 0;
}
