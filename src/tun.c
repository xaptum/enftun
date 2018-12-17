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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/if_tun.h>
#include <net/if.h>
#include <netinet/in.h>

#include "exec.h"
#include "ip.h"
#include "log.h"
#include "memory.h"
#include "tun.h"

struct enftun_channel_ops enftun_tun_ops =
{
   .read    = (int (*)(void*, struct enftun_packet*)) enftun_tun_read_packet,
   .write   = (int (*)(void*, struct enftun_packet*)) enftun_tun_write_packet,
   .prepare = NULL
};

int
enftun_tun_init(struct enftun_tun* tun)
{
    CLEAR(*tun);
    return 0;
}

int
enftun_tun_free(struct enftun_tun* tun)
{
    if (tun->name)
        free(tun->name);
    CLEAR(*tun);
    return 0;
}

int
enftun_tun_open(struct enftun_tun* tun,
                const char* dev, const char* dev_node)
{
    struct ifreq ifr;
    int rc;

    if ((tun->fd = open(dev_node, O_RDWR)) < 0)
    {
        rc = errno;
        enftun_log_error("Cannot open TUN dev %s: %s\n",
                         dev_node,
                         strerror(rc));
        goto out;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if (ioctl(tun->fd, TUNSETIFF, (void *) &ifr) < 0)
    {
        enftun_log_error("Cannot ioctl TUNSETIFF on dev %s: %s\n",
                         dev,
                         strerror(errno));
        rc = -errno;
        goto close;
    }

    tun->name = strdup(ifr.ifr_name);

    if (fcntl(tun->fd, F_SETFL, O_NONBLOCK) < 0)
    {
        enftun_log_error("Cannot fcntl O_NONBLOCK on dev %s: %s\n",
                         dev,
                         strerror(errno));
        rc = -errno;
        goto close;
    }

    if (fcntl(tun->fd, F_SETFD, FD_CLOEXEC) < 0)
    {
        enftun_log_error("Cannot fcntl FD_CLOEXEC on dev %s: %s\n",
                         dev,
                         strerror(errno));
        rc = -errno;
        goto close;
    }

    enftun_log_info("Opened tun device %s\n", tun->name);

    rc = 0;
    goto out;

 close:
    close(tun->fd);

 out:
    return rc;
}

int
enftun_tun_close(struct enftun_tun* tun)
{
    if (close(tun->fd) < 0)
        return -errno;
    else
        return 0;
}

int
enftun_tun_set_ip6(struct enftun_tun* tun,
                   const char* ip_path, const struct in6_addr* ip6)
{
    int rc;
    char addr[45+1+3+1]; // max addr + '/' + max prefix + null term

    if ((rc = ip6_prefix_str(ip6, 128, addr, sizeof(addr))) < 0)
        return rc;

    const char* argv[] = { ip_path, "-6", "addr", "replace", addr, "dev", tun->name, 0 };
    const char* envp[] = { 0 };

    if ((rc = enftun_exec(argv, envp)) < 0)
    {
        enftun_log_error("Failed to set the address of %s\n", tun->name);
        return rc;
    }

    return 0;
}

int
enftun_tun_read(struct enftun_tun* tun,
                uint8_t* buf, size_t len)
{
    int rc;
    if ((rc = read(tun->fd, buf, len)) < 0)
        return -errno;
    else
        return rc;
}

int
enftun_tun_write(struct enftun_tun* tun,
                 uint8_t* buf, size_t len)
{
    int rc;
    if ((rc = write(tun->fd, buf, len)) < 0)
        return -errno;
    else
        return rc;
}

int
enftun_tun_read_packet(struct enftun_tun* tun, struct enftun_packet* pkt)
{
    int rc;

    rc = enftun_tun_read(tun, pkt->data, enftun_packet_tailroom(pkt));
    if (rc < 0)
        return rc;

    if (rc == 0)
        return -EAGAIN;

    enftun_packet_insert_tail(pkt, rc);
    return 0;
}

int
enftun_tun_write_packet(struct enftun_tun* tun, struct enftun_packet* pkt)
{
    int rc;

    rc = enftun_tun_write(tun, pkt->data, pkt->size);
    if (rc < 0)
        return rc;

    enftun_packet_remove_tail(pkt, rc);
    return 0;
}
