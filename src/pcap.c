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

#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "log.h"
#include "memory.h"
#include "packet.h"
#include "pcap.h"

struct pcap_hdr
{
    uint32_t magicnum;
    uint16_t vermajor;
    uint16_t verminor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
};

struct pcap_rec
{
    uint32_t timesec;
    uint32_t timeusec;
    uint32_t incllen;
    uint32_t origlen;
};

#define MAGICNUM 0xA1B2C3D4
#define VERMAJOR 2
#define VERMINOR 4
#define LINKTYPE_RAW 101

static int
write_pcap_header(FILE* f)
{
    struct pcap_hdr hdr = {.magicnum = MAGICNUM,
                           .vermajor = VERMAJOR,
                           .verminor = VERMINOR,
                           .thiszone = 0,
                           .sigfigs  = 0,
                           .snaplen  = 65535,
                           .linktype = LINKTYPE_RAW};

    int rc = fwrite(&hdr, sizeof(hdr), 1, f);
    if (rc != 1)
        return -1;

    return 0;
}

static int
write_pcap_record(FILE* f, uint8_t* buf, size_t len)
{
    int rc;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    struct pcap_rec rec = {.timesec  = ts.tv_sec,
                           .timeusec = round(ts.tv_nsec / 1.0e3),
                           .incllen  = len,
                           .origlen  = len};

    rc = fwrite(&rec, sizeof(rec), 1, f);
    if (rc != 1)
        return -1;

    rc = fwrite(buf, 1, len, f);
    if (rc != 1)
        return -1;

    return 0;
}

int
enftun_pcap_init(struct enftun_pcap* pcap, int enable, const char* path)
{
    CLEAR(*pcap);

    if (!enable)
        return 1;

    pcap->file = fopen(path, "ab");
    if (pcap->file == NULL)
    {
        enftun_log_error("Failed to open pcap file %s: %d\n", path, errno);
        goto err;
    }

    setvbuf(pcap->file, NULL, _IONBF, 0);

    int rc = write_pcap_header(pcap->file);
    if (rc < 0)
    {
        enftun_log_error("Failed to write to pcap file: %d\n",
                         ferror(pcap->file));
        goto close;
    }

    pcap->enabled = 1;

    return 0;

close:
    fclose(pcap->file);

err:
    return -1;
}

int
enftun_pcap_free(struct enftun_pcap* pcap)
{
    if (pcap->enabled)
        fclose(pcap->file);

    return 0;
}

int
enftun_pcap_trace(struct enftun_pcap* pcap, struct enftun_packet* pkt)
{
    int rc = 0;
    if (pcap->enabled)
        rc = write_pcap_record(pcap->file, pkt->data, pkt->size);

    return rc;
}
