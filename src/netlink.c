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

#include "netlink.h"

#include <net/if.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "context.h"

static
void
parse_rtattr(struct rtattr* tb[], int max, struct rtattr* rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr*)* (max + 1));

    while (RTA_OK(rta, len)) {          // while not end of the message
        if (rta->rta_type <= max) {
            tb[rta->rta_type] = rta;    // read attr
        }
        rta = RTA_NEXT(rta,len);        // get next attr
    }
}

static
char*
get_if_name(struct nlmsghdr* nl_message)
{
    struct ifinfomsg* if_info;
    struct rtattr* tb[IFLA_MAX + 1];

    if_info = (struct ifinfomsg*) NLMSG_DATA(nl_message);

    parse_rtattr(tb, IFLA_MAX, IFLA_RTA(if_info), nl_message->nlmsg_len);

    if (tb[IFLA_IFNAME]) {
        return (char*)RTA_DATA(tb[IFLA_IFNAME]);
    }
    return NULL;
}

static
char*
get_if_addr(struct nlmsghdr* nl_message, char* if_address, int len)
{
    struct ifaddrmsg* if_addr;
    struct rtattr* tba[IFA_MAX+1];

    if_addr = (struct ifaddrmsg*)NLMSG_DATA(nl_message);

    parse_rtattr(tba, IFA_MAX, IFA_RTA(if_addr), nl_message->nlmsg_len);

    if (tba[IFA_LOCAL]) {
        inet_ntop(AF_INET, RTA_DATA(tba[IFA_LOCAL]), if_address, len);
    } else {
        enftun_log_error("Cannot get local address\n");
    }

    return if_address;
}

static
char*
get_if_status(struct nlmsghdr* nl_message)
{
    struct ifinfomsg* if_info;

    if_info = (struct ifinfomsg*) NLMSG_DATA(nl_message);

    if (if_info->ifi_flags & IFF_UP) {
        if (if_info->ifi_flags & IFF_RUNNING) {
            return (char*)"UP RUNNING";
        } else {
            return (char*)"UP NOT RUNNING";
        }
    } else {
        if (if_info->ifi_flags & IFF_RUNNING) {
            return (char*)"DOWN RUNNING";
        } else {
            return (char*)"DOWN NOT RUNNING";
        }
    }
}

static
int
handle_route_change(struct enftun_netlink* nl)
{
    enftun_log_info("Change in routing\n");
    nl->on_change(nl);

    return 0;
}

static
int
handle_addr_change(struct enftun_netlink* nl, struct nlmsghdr* nl_message)
{
    // get interface name
    char* if_name = (char*) "";
    if_name = get_if_name(nl_message);
    if (if_name == NULL) {
        enftun_log_error("Cannot get interface's name\n");
        return -1;
    }

    if (0 == strcmp(if_name, nl->tun_name))
        goto ignore_interface_addr;

    // get interface address
    char if_address[256];
    char* addr_ptr = if_address;

    addr_ptr = get_if_addr(nl_message, if_address, sizeof(if_address));

    switch (nl_message->nlmsg_type) {
        case RTM_DELADDR:
            enftun_log_info("Interface %s: address was removed\n", if_name);
            nl->on_change(nl);
            break;

        case RTM_NEWADDR:
            enftun_log_info("Interface %s: new address was assigned: %s\n", if_name, addr_ptr);
            nl->on_change(nl);
            break;
    }

ignore_interface_addr:
    return 0;
}

static
int
handle_link_change(struct enftun_netlink* nl, struct nlmsghdr* nl_message)
{
    //get interface name
    char* if_name = (char*) "";
    if_name = get_if_name(nl_message);
    if (if_name == NULL){
        enftun_log_error("Cannot get interface's name\n");
        return -1;
    }

    if (0 == strcmp(if_name, nl->tun_name))
        goto ignore_interface_link;

    // get interface state
    char* if_status_flag = get_if_status(nl_message);

    switch (nl_message->nlmsg_type) {
        case RTM_DELLINK:
            enftun_log_info("Network interface %s was removed\n", if_name);
            nl->on_change(nl);
            break;

        case RTM_NEWLINK:
            enftun_log_info("New network interface %s, state: %s\n", if_name, if_status_flag);
            nl->on_change(nl);
            break;
    }

ignore_interface_link:
    return 0;
}

int
enftun_netlink_loop(struct enftun_netlink* nl)
{
    (void) nl;
    ssize_t bytes_in_msg = recvmsg(nl->fd, &nl->msg, MSG_DONTWAIT);
    if (bytes_in_msg < 0 || (nl->msg.msg_namelen != sizeof(nl->sock_addr))) {
        return -1;
    }

    struct nlmsghdr* nl_message;
    nl_message = (struct nlmsghdr*)nl->buffer;

    while (bytes_in_msg >= (ssize_t)sizeof(*nl_message)) {
        int length_msghdr = nl_message->nlmsg_len;
        int length_msg = length_msghdr - sizeof(*nl_message);

        if ((length_msg < 0) || (length_msghdr > bytes_in_msg)) {
            enftun_log_error("Invalid message length: %i\n", length_msghdr);
            continue;
        }
        int rc = 0;
        if ((nl_message->nlmsg_type == RTM_NEWROUTE) || (nl_message->nlmsg_type == RTM_DELROUTE)){
            rc = handle_route_change(nl);
        } else if ((nl_message->nlmsg_type == RTM_NEWADDR) || (nl_message->nlmsg_type == RTM_DELADDR)) {
            rc = handle_addr_change(nl, nl_message);
        } else if ((nl_message->nlmsg_type == RTM_NEWLINK) || (nl_message->nlmsg_type == RTM_DELLINK)) {
            rc = handle_link_change(nl, nl_message);
        }
        if (0 != rc){
            return -1;
        }

        // align offsets by the message length, this is important
        bytes_in_msg -= NLMSG_ALIGN(length_msghdr);

        nl_message = (struct nlmsghdr*)((char*)nl_message + NLMSG_ALIGN(length_msghdr));
    }
    return 0;
}

static
void
on_poll(uv_poll_t* handle, int status, int events)
{
    (void) status;
    (void) events;
    struct enftun_netlink* nl = handle->data;

    if (status < 0)
        return;
    if (0 == status)
        enftun_netlink_loop(nl);
}

int
enftun_netlink_init(struct enftun_netlink* nl, uv_loop_t* loop, void* ctx, char* tun_name)
{
    nl->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl->fd < 0) {
        return -1;
    }

    nl->io_vector.iov_base = nl->buffer;
    nl->io_vector.iov_len = sizeof(nl->buffer);

    memset(&nl->sock_addr, 0, sizeof(struct sockaddr_nl));

    nl->sock_addr.nl_family = AF_NETLINK;
    nl->sock_addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    nl->sock_addr.nl_pid = getpid();

    nl->msg.msg_name = &nl->sock_addr;
    nl->msg.msg_namelen = sizeof(nl->sock_addr);
    nl->msg.msg_iov = &nl->io_vector;
    nl->msg.msg_iovlen = 1;

    if (bind(nl->fd, (struct sockaddr*)&nl->sock_addr, sizeof(struct sockaddr_nl)) < 0) {
        close(nl->fd);
        return -1;
    }

    nl->tun_name = tun_name;

    nl->data = ctx;

    nl->poll.data = nl;
    int rc = uv_poll_init(loop, &nl->poll, nl->fd);

    return rc;
}

int
enftun_netlink_free(struct enftun_netlink* nl)
{
    close(nl->fd);
    return 0;
}

int
enftun_netlink_start(struct enftun_netlink* nl, enftun_netlink_on_change on_change)
{
    int rc;
    nl->on_change = on_change;
    rc = uv_poll_start(&nl->poll, UV_READABLE, on_poll);

    return rc;
}

int
enftun_netlink_stop(struct enftun_netlink* nl)
{
    int rc = uv_poll_stop(&nl->poll);

    return rc;
}
