/*
 * Copyright 2021 Xaptum, Inc.
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

#ifndef ENFTUN_SLIRP_H
#define ENFTUN_SLIRP_H

#include <slirp/libvdeslirp.h>

#include "channel.h"
#include "packet.h"

struct enftun_slirp
{
    SlirpConfig config;
    struct vdeslirp* slirp;
};

extern struct enftun_channel_ops enftun_slirp_ops;

int
enftun_slirp_init(struct enftun_slirp* slirp);

int
enftun_slirp_free(struct enftun_slirp* slirp);

int
enftun_slirp_open(struct enftun_slirp* slirp);

int
enftun_slirp_close(struct enftun_slirp* slirp);

int
enftun_slirp_read(struct enftun_slirp* slirp, uint8_t* buf, size_t len);

int
enftun_slirp_write(struct enftun_slirp* slirp, uint8_t* buf, size_t len);

int
enftun_slirp_fd(struct enftun_slirp* slirp);

int
enftun_slirp_read_packet(struct enftun_slirp* slirp, struct enftun_packet* pkt);

int
enftun_slirp_write_packet(struct enftun_slirp* slirp,
                          struct enftun_packet* pkt);

#endif
