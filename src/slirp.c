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

#include <net/ethernet.h>
#include <stdint.h>

#include "memory.h"
#include "slirp.h"

static const uint8_t host_ethaddr[ETH_ALEN] = {0x52, 0x55, 0x0a,
                                               0x00, 0x02, 0x02};

static const uint8_t guest_ethaddr[ETH_ALEN] = {0x52, 0x55, 0x0a,
                                                0x00, 0x03, 0x03};

struct enftun_channel_ops enftun_slirp_ops = {
    .fd    = (int (*)(void*)) enftun_slirp_fd,
    .read  = (int (*)(void*, struct enftun_packet*)) enftun_slirp_read_packet,
    .write = (int (*)(void*, struct enftun_packet*)) enftun_slirp_write_packet,
    .prepare = NULL,
    .pending = NULL};

int
enftun_slirp_init(struct enftun_slirp* slirp)
{
    CLEAR(*slirp);
    return 0;
}

int
enftun_slirp_free(struct enftun_slirp* slirp)
{
    CLEAR(*slirp);
    return 0;
}

int
enftun_slirp_open(struct enftun_slirp* slirp)
{
    vdeslirp_init(&slirp->config, VDE_INIT_DEFAULT);

    slirp->config.version               = 3;
    slirp->config.in_enabled            = 0;
    slirp->config.if_mtu                = 1280;
    slirp->config.if_mru                = 1280;
    slirp->config.disable_host_loopback = 1;
    slirp->config.disable_dns           = 1;

    slirp->slirp = vdeslirp_open(&slirp->config);
    if (!slirp->slirp)
        return -1;

    return 0;
}

int
enftun_slirp_close(struct enftun_slirp* slirp)
{
    vdeslirp_close(slirp->slirp);
    return 0;
}

int
enftun_slirp_read(struct enftun_slirp* slirp, uint8_t* buf, size_t len)
{
    int rc;
    if ((rc = vdeslirp_recv(slirp->slirp, buf, len)) < 0)
        return -errno;
    else
        return rc;
}

int
enftun_slirp_write(struct enftun_slirp* slirp, uint8_t* buf, size_t len)
{
    int rc;
    if ((rc = vdeslirp_send(slirp->slirp, buf, len)) < 0)
        return -errno;
    else
        return rc;
}

static int
insert_eth_header(struct enftun_packet* pkt)
{
    struct ether_header* eth = enftun_packet_insert_head(pkt, ETHER_HDR_LEN);
    if (eth == NULL)
        return -1;

    memcpy(eth->ether_dhost, host_ethaddr, sizeof(eth->ether_dhost));
    memcpy(eth->ether_shost, guest_ethaddr, sizeof(eth->ether_shost));
    eth->ether_type = htons(ETH_P_IPV6);

    return 0;
}

static void
strip_eth_header(struct enftun_packet* pkt)
{
    enftun_packet_remove_head(pkt, ETHER_HDR_LEN);
}

int
enftun_slirp_fd(struct enftun_slirp* slirp)
{
    return vdeslirp_fd(slirp->slirp);
}

int
enftun_slirp_read_packet(struct enftun_slirp* slirp, struct enftun_packet* pkt)
{
    int rc;

    /*
     * Ensure the 14-byte ethernet header is half-word aligned, so
     * that the actual packet payload will be word aligned.
     */
    enftun_packet_reserve_head(pkt, 2);

    rc = enftun_slirp_read(slirp, pkt->data, enftun_packet_tailroom(pkt));
    if (rc < 0)
        return rc;

    if (rc == 0)
        return -EAGAIN;

    enftun_packet_insert_tail(pkt, rc);

    strip_eth_header(pkt);

    return 0;
}

int
enftun_slirp_write_packet(struct enftun_slirp* slirp, struct enftun_packet* pkt)
{
    int rc;

    rc = insert_eth_header(pkt);
    if (rc < 0)
        return rc;

    rc = enftun_slirp_write(slirp, pkt->data, pkt->size);
    if (rc < 0)
        return rc;

    enftun_packet_remove_head(pkt, rc);
    return 0;
}
