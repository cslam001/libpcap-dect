/*
 * Copyright (C) 2009 Patrick McHardy <kaber@trash.net>
 *
 * Licensed under the same license as libpcap itself.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pcap-int.h"
#include "pcap-dect-linux.h"

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <linux/types.h>
#include <linux/dect.h>
#include <linux/netlink.h>
#include <netlink/cache.h>
#include <netlink/dect/cell.h>

#define PF_DECT		38
#define AF_DECT		PF_DECT
#define SOL_DECT	279

struct cb_args {
	pcap_if_t	**alldevsp;
	char		*err_str;
	bool		err;
};

static void add_cell_cb(struct nl_object *obj, void *arg)
{
	struct cb_args *args = arg;
	char dev_name[32];

	if (args->err)
		return;

	snprintf(dev_name, sizeof(dev_name), "dect-%s",
		 nl_dect_cell_get_name((struct nl_dect_cell *)obj));

	if (pcap_add_if(args->alldevsp, dev_name, 0, NULL, args->err_str) < 0)
		args->err = true;
}

int dect_platform_finddevs(pcap_if_t **alldevsp, char *err_str)
{
	struct nl_sock *sock;
	struct nl_cache *cell_cache;
	struct cb_args args = {
		.alldevsp	= alldevsp,
		.err_str	= err_str,
	};

	sock = nl_socket_alloc();
	if (sock == NULL) {
		snprintf(err_str, PCAP_ERRBUF_SIZE, "socket: %s",
			 pcap_strerror(errno));
		return -1;
	}
	if (nl_connect(sock, NETLINK_DECT) < 0) {
		snprintf(err_str, PCAP_ERRBUF_SIZE, "connect: %s",
			 pcap_strerror(errno));
		return -1;
	}
	if (nl_dect_cell_alloc_cache(sock, &cell_cache) < 0) {
		snprintf(err_str, PCAP_ERRBUF_SIZE, "cache: %s",
			 pcap_strerror(errno));
		return -1;
	}

	nl_cache_foreach(cell_cache, add_cell_cb, &args);
	nl_socket_free(sock);

	return args.err ? -1 : 0;
}

/*
 * compatible header to what wireshark is expecting from the CoA
 * character device for now.
 */
struct dect_dummy_hdr {
	uint8_t		etheraddrs[2 * 6];
	uint16_t	ethertype;

	uint8_t		trxmode;
	uint8_t		channel;
	uint16_t	slot;
	uint8_t		frame;
	uint8_t		rssi;
	uint8_t		preamble[3];
	uint16_t	packettype;
} __attribute__((packed));

static int dect_read_linux(pcap_t *handle, int max_packets,
			   pcap_handler callback, u_char *user)
{
	struct pcap_pkthdr hdr;
	struct dect_dummy_hdr *dhdr;
	struct iovec iov;
	struct msghdr msg;
	struct dect_raw_auxdata *aux;
	struct cmsghdr *cmsg;
	union {
		struct cmsghdr		cmsg;
		char			buf[CMSG_SPACE(sizeof(*aux))];
	} cmsg_buf;
	ssize_t len;

	/* refuse anything below dummy header size for simplicity */
	if (handle->bufsize < sizeof(*dhdr))
		return -1;

	dhdr = (struct dect_dummy_hdr *)handle->buffer;
	memset(dhdr, 0, sizeof(*dhdr));
	dhdr->ethertype = 0x2323;
	dhdr->trxmode	= 0;
	dhdr->channel	= 0;

	msg.msg_name		= NULL;
	msg.msg_namelen		= 0;
	msg.msg_iov		= &iov;
	msg.msg_iovlen		= 1;
	msg.msg_control		= &cmsg_buf;
	msg.msg_controllen	= sizeof(cmsg_buf);
	msg.msg_flags		= 0;

	iov.iov_len		= handle->bufsize - sizeof(*dhdr);
	iov.iov_base		= handle->buffer + sizeof(*dhdr);

	do {
		if (handle->break_loop) {
			handle->break_loop = 0;
			return -2;
		}

		len = recvmsg(handle->fd, &msg, 0);
	} while (len == -1 && (errno == EINTR || errno == ENETDOWN));

	if (len == -1) {
		if (errno == EAGAIN)
			return 0;
		else {
			snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
				 "recvfrom: %s", pcap_strerror(errno));
			return -1;
		}
	}

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
	     cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level != SOL_DECT ||
		    cmsg->cmsg_type != DECT_RAW_AUXDATA ||
		    cmsg->cmsg_len < CMSG_LEN(sizeof(*aux)))
			continue;

		aux = (struct dect_raw_auxdata *)CMSG_DATA(cmsg);
		dhdr->slot = htons(aux->slot);
		dhdr->rssi = aux->rssi;
		dhdr->frame = aux->frame;
		if (aux->slot < 12)
			dhdr->packettype = htons(0xe98a);
		else
			dhdr->packettype = htons(0x1675);
	}

	gettimeofday(&hdr.ts, NULL);
	hdr.caplen = len + sizeof(*dhdr);
	hdr.len    = len + sizeof(*dhdr);
	callback(user, &hdr, handle->buffer);
	return 1;
}

static int dect_setfilter_linux(pcap_t *handle, struct bpf_program *fp)
{
	return 0;
}

static int dect_setdirection_linux(pcap_t *handle, pcap_direction_t d)
{
	handle->direction = d;
	return 0;
}

static int dect_activate(pcap_t *handle)
{
	struct sockaddr_dect da;

	handle->bufsize		= handle->snapshot;
	handle->offset		= 0;
#if 0
	handle->linktype	= DLT_DECT_LINUX;
#else
	handle->linktype	= DLT_EN10MB;
#endif

	handle->inject_op	= NULL;
	handle->setfilter_op	= dect_setfilter_linux;
	handle->setdirection_op = dect_setdirection_linux;
	handle->set_datalink_op	= NULL;
	handle->getnonblock_op	= pcap_getnonblock_fd;
	handle->setnonblock_op	= pcap_setnonblock_fd;
	handle->read_op		= dect_read_linux;

	handle->fd = socket(PF_DECT, SOCK_RAW, 0);
	if (handle->fd < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Can't open PF_DECT socket: %s",
			 pcap_strerror(errno));
		return PCAP_ERROR;
	}

	memset(&da, 0, sizeof(da));
	da.dect_family = AF_DECT;
	if (bind(handle->fd, (struct sockaddr *)&da, sizeof(da)) < 0) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Can't bind PF_DECT socket: %s",
			 pcap_strerror(errno));
		return PCAP_ERROR;
	}

	handle->selectable_fd = handle->fd;
	handle->buffer = malloc(handle->bufsize);
	if (!handle->buffer) {
		snprintf(handle->errbuf, PCAP_ERRBUF_SIZE,
			 "Can't allocate packet buffer: %s",
			 pcap_strerror(errno));
		return PCAP_ERROR;
	}
	return 0;
}

pcap_t *dect_create(const char *device, char *ebuf)
{
	pcap_t *p;

	p = pcap_create_common(device, ebuf);
	if (p == NULL)
		return NULL;

	p->activate_op = dect_activate;
	return p;
}
