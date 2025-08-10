#include "btavctpd.h"

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/endian.h>
#include <sys/poll.h>

#define L2CAP_SOCKET_CHECKED 1
#include <bluetooth.h>
#include <sdp.h>

static bdaddr_t remote = {0};    /* Address of the remote side */
static int dflag = 0;            /* -d was specified (no daemon) */
static int pflag = 0;            /* -p was specfied (use playerctl) */

/* print a usage message */
static void
usage(void)
{
	fprintf(stderr, "usage: %s [-d] [-p] -h address\n", getprogname());
}

static void
bterr(char const *const fmt, ...)
{
	va_list args;
	char buffer[128] = {0};

	va_start(args, fmt);
	vsnprintf(buffer, sizeof buffer, fmt, args);
	va_end(args);

	syslog(LOG_ERR, "%s: %s", buffer, strerror(errno));

	exit(1);
}

void
btwarnx(char const *const fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	vsyslog(LOG_WARNING, fmt, args);
	va_end(args);
}

/* Parse command line options */
static void
parseflags(int *argc, char ***argv)
{
	int ch;
	struct option options[] = {
		{ "host", required_argument, NULL, 'h' },
		{ "no-daemon", no_argument, NULL, 'd' },
		{0},
	};

	while ((ch = getopt_long(*argc, *argv, "+dph:", options, NULL)) != -1) {
		switch (ch) {
		case 'h': {
			/* try as raw address first */
			if (bt_aton(optarg, &remote))
				break;

			/* otherwise do a hostname lookup */
			struct hostent *ent = bt_gethostbyname(optarg);
			if (!ent)
				errx(1, "%s: bad hostname or address", optarg);

			assert(sizeof(remote) == ent->h_length);
			memcpy(&remote, ent->h_addr_list[0], sizeof(remote));
		} break;
		case 'd': {
			dflag = 1;
		} break;
		case 'p': {
			pflag = 1;
		} break;
		default: {
			usage();
			exit(1);
		} break;
		}
	}

	*argc -= optind;
	*argv += optind;
}

static void
reply_passthru(struct ctx *ctx, uint8_t const tid,
               uint8_t const ctype, uint8_t const operation)
{
	uint8_t buffer[8] = {0};
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avc_header *avc = (struct avc_header *)(ctp_hdr + 1);
	enum { pkt_len = sizeof(*ctp_hdr) + sizeof(*avc) };

	static_assert(pkt_len <= sizeof(buffer), "Buffer too smol");

	ctp_hdr->id = 0x02 | (tid << 4);
	ctp_hdr->pid = htobe16(0x110e);

	avc->ctype = ctype;
	avc->subunit = (0x9 << 3) /* subunit type */ | 0x0 /* subunit id */;
        avc->opcode = AVRCP_OPCODE_PASSTHRU;
        avc->operation = operation;
        avc->data_length = 0;

	size_t rc = send(ctx->fd, buffer, pkt_len, 0);
	if (rc < 0)
		bterr("send failed");
}

static void
do_play(struct ctx *ctx)
{
	if (pflag) {
		playerctl_play(ctx);
	} else {
		system("xdotool key XF86AudioPlay");
	}
}

static void
do_playpause(struct ctx *ctx)
{
	if (pflag) {
		playerctl_playpause(ctx);
	} else {
		system("xdotool key XF86AudioPlay");
	}
}

static void
do_next(struct ctx *ctx)
{
	if (pflag) {
		playerctl_next(ctx);
	} else {
		system("xdotool key XF86AudioNext");
	}
}

static void
do_prev(struct ctx *ctx)
{
	if (pflag) {
		playerctl_prev(ctx);
	} else {
		system("xdotool key XF86AudioPrev");
	}
}

static void
handle_passthru(struct ctx *ctx, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avc_header *avc = (struct avc_header *)(ctp_hdr + 1);

	/* Button was released */
	if (avc->operation & 0x80) {
		syslog(LOG_INFO, "Button release event");
		goto ack;
	}

	switch (avc->operation & 0x7F) {
	case AVC_PLAY:
		syslog(LOG_INFO, "Received Play Event");
		do_play(ctx);
		goto ack;
	case AVC_PAUSE:
		syslog(LOG_INFO, "Received Pause Event");
		do_playpause(ctx);
		goto ack;
	case AVC_NEXT:
		syslog(LOG_INFO, "Received Next Event");
		do_next(ctx);
		goto ack;
	case AVC_PREV:
		syslog(LOG_INFO, "Received Previous Event");
		do_prev(ctx);
		goto ack;
	case AVC_STOP:
		syslog(LOG_INFO, "Received Stop Event");
		puts("Stopping");
		/* FALLTHRU */
	ack:
		reply_passthru(ctx, avctp_tid(ctp_hdr), AVRCP_CTYPE_ACCEPTED,
		               avc->operation);
		break;
	default:
		btwarnx("rejecting unknown operation: 0x%"PRIx8,
		        avc->operation & 0x7F);

		reply_passthru(ctx, avctp_tid(ctp_hdr), AVRCP_CTYPE_REJECTED,
		               avc->operation);
		break;
	}
}

void
bt_send_avrcp_change_event(struct ctx *ctx, uint8_t tid, uint8_t event_id,
                           uint8_t status)
{
	char buffer[64] = {0};
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	struct avrcp_event *evt = (struct avrcp_event *)(rcp_hdr + 1);

	enum { packet_len = sizeof(*ctp_hdr) + sizeof(*rcp_hdr) + sizeof(*evt) };
	static_assert(packet_len <= sizeof(buffer), "buffer too smol");

	btwarnx("[0x%"PRIx8"]: change for evt 0x%"PRIx8": 0x%"PRIx8"\n",
	        tid, event_id, status);

	ctp_hdr->id = 0x02 | (tid << 4); /* this is a response, single-frame */
	ctp_hdr->pid = htobe16(0x110e);

	rcp_hdr->ctype = AVRCP_CTYPE_CHANGED;
	rcp_hdr->subunit = (0x9 << 3) /* subunit type */ | 0x0 /* subunit id */;
	rcp_hdr->opcode = AVRCP_OPCODE_VENDOR;
	rcp_hdr->companyid[0] = 0x00;
	rcp_hdr->companyid[1] = 0x19;
	rcp_hdr->companyid[2] = 0x58;
	rcp_hdr->pdu_id = AVRCP_PDUID_REGISTERNOTIFICATION;
	rcp_hdr->packet_type = 0; /* single unfragmented */
	rcp_hdr->param_len = htobe16(sizeof(*evt));

	evt->event_id = event_id;
	evt->params[0] = status;

	size_t rc = send(ctx->fd, buffer, packet_len, 0);
	if (rc < 0)
		bterr("send failed");
}

void
bt_send_avrcp_interim(struct ctx *ctx, uint8_t tid, uint8_t event_id,
                      uint8_t status)
{
	char buffer[64] = {0};
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	struct avrcp_event *evt = (struct avrcp_event *)(rcp_hdr + 1);

	enum { packet_len = sizeof(*ctp_hdr) + sizeof(*rcp_hdr) + sizeof(*evt) };
	static_assert(packet_len <= sizeof(buffer), "buffer too smol");

	btwarnx("[0x%"PRIx8"]: interim for evt 0x%"PRIx8": 0x%"PRIx8"\n",
	        tid, event_id, status);

	ctp_hdr->id = 0x02 | (tid << 4); /* this is a response, single-frame */
	ctp_hdr->pid = htobe16(0x110e);

	rcp_hdr->ctype = AVRCP_CTYPE_INTERIM;
	rcp_hdr->subunit = (0x9 << 3) /* subunit type */ | 0x0 /* subunit id */;
	rcp_hdr->opcode = AVRCP_OPCODE_VENDOR;
	rcp_hdr->companyid[0] = 0x00;
	rcp_hdr->companyid[1] = 0x19;
	rcp_hdr->companyid[2] = 0x58;
	rcp_hdr->pdu_id = AVRCP_PDUID_REGISTERNOTIFICATION;
	rcp_hdr->packet_type = 0; /* single unfragmented */
	rcp_hdr->param_len = htobe16(sizeof(*evt));

	evt->event_id = event_id;
	evt->params[0] = status;

	size_t rc = send(ctx->fd, buffer, packet_len, 0);
	if (rc < 0)
		bterr("send failed");
}

static void
handle_event_registration(struct ctx *ctx, uint8_t const *buffer,
                          size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	struct avrcp_reg_evt_payload *evt = (struct avrcp_reg_evt_payload *)(rcp_hdr + 1);
	uint8_t bit_offset;

	bit_offset = evt->evt_id - 1;
	if (bit_offset >= 0xd) {
		btwarnx("bad event id from peer");
		return;
	}

	/* respond with interim if possible and needed */
	if (pflag) {
		playerctl_event_registered(
			ctx, avctp_tid(ctp_hdr),
			evt->evt_id);
	}

	/* now update the event mask */
	btwarnx("Peer registed %s event", event_name(evt->evt_id));
	ctx->event_mask |= (1 << bit_offset);
}

static void
handle_notify_command(struct ctx *ctx, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);

	switch (rcp_hdr->pdu_id) {
	case AVRCP_PDUID_REGISTERNOTIFICATION: {
		handle_event_registration(ctx, buffer, buffer_size);
	} break;
	default: {
		btwarnx("unhandled notify PDU: 0x%"PRIx8, rcp_hdr->pdu_id);
	} break;
	}
}

static void
handle_command(struct ctx *ctx, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);

	if (rcp_hdr->ctype == AVRCP_CTYPE_CONTROL) {
		if (rcp_hdr->opcode == AVRCP_OPCODE_PASSTHRU)
			handle_passthru(ctx, buffer, buffer_size);
		else
			btwarnx("unhandled control command: 0x%"PRIx8,
			        rcp_hdr->opcode);
	} else if (rcp_hdr->ctype == AVRCP_CTYPE_NOTIFY) {
		if (rcp_hdr->subunit != (0x09 << 3) ||
		    rcp_hdr->opcode != 0 ||
		    rcp_hdr->companyid[0] != 0 ||
		    rcp_hdr->companyid[1] != 0x19 ||
		    rcp_hdr->companyid[2] != 0x58) {
			btwarnx("bad notify command received from peer");
			return;
		}

		handle_notify_command(ctx, buffer, buffer_size);
	} else {
		btwarnx("Unhandled command with ctype 0x%"PRIx8,
		        rcp_hdr->ctype);
	}
}

static void
register_notifications(struct ctx *ctx, uint8_t const evt_id)
{
	uint8_t buffer[64] = {0};
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	struct avrcp_reg_evt_payload *rep = (struct avrcp_reg_evt_payload *)(rcp_hdr + 1);
	enum { packet_len = sizeof(*ctp_hdr) + sizeof(*rcp_hdr) + sizeof(*rep) };

	static_assert(packet_len <= sizeof(buffer), "buffer too smol");

	ctp_hdr->pid = htobe16(0x110e);

	rcp_hdr->ctype = AVRCP_CTYPE_NOTIFY;
	rcp_hdr->subunit = (0x9 << 3) /* subunit type */ | 0x0 /* subunit id */;
	rcp_hdr->opcode = AVRCP_OPCODE_VENDOR; /* vendor specific */
	rcp_hdr->companyid[0] = 0x00;
	rcp_hdr->companyid[1] = 0x19;
	rcp_hdr->companyid[2] = 0x58;
	rcp_hdr->pdu_id = AVRCP_PDUID_REGISTERNOTIFICATION;
	rcp_hdr->packet_type = 0; /* single unfragmented */
	rcp_hdr->param_len = htobe16(sizeof(*rep));

	rep->evt_id = evt_id;

	ssize_t n = send(ctx->fd, buffer, packet_len, 0);
	if (n < 0)
		bterr("send");
}

static void
handle_supported_event(struct ctx *ctx, uint8_t evt)
{
	syslog(LOG_INFO, "Register notifications for event %s",
	       event_name(evt));
	register_notifications(ctx, evt);
}

static void
handle_stable_response(struct ctx *ctx, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);

	switch (rcp_hdr->pdu_id) {
	case AVRCP_PDUID_GETCAPABILITIES: {
		uint8_t *caps = (uint8_t *)(rcp_hdr + 1);

		if (rcp_hdr->param_len < 2) {
			btwarnx("Too few params in AVRCP_PDUID_GETCAPABILITIES response");
			return;
		}

		if (*caps == 0x03) /* Events Supported */ {
			struct avrcp_event_list *evt_list =
				(struct avrcp_event_list *)(caps + 1);

			for (uint8_t i = 0; i < evt_list->n_evts; ++i) {
				handle_supported_event(ctx, evt_list->evts[i]);
			}
		}
	} break;
	case AVRCP_PDUID_REGISTERNOTIFICATION: {
		btwarnx("Stable RegisterNotification response");
	} break;
	}
}

static void
handle_change_notification(struct ctx *ctx, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	struct avrcp_event *evt = (struct avrcp_event *)(rcp_hdr + 1);

	switch (evt->event_id) {
	case AVRCP_EVENT_VOLUME_CHANGED: {
		uint8_t vol = evt->params[0] & 0x7F; /* RFA bit masked off */
		double perc = ((double)(vol) / (double)(0x7F)) * 100.0;
		syslog(LOG_INFO, "Volume changed to %lf%%", perc);

		/* re-register the event */
		register_notifications(ctx, evt->event_id);
	} break;
	default:
		btwarnx("Unhandled change event");
		break;
	}
}

static void
handle_response(struct ctx *ctx, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);

	if (rcp_hdr->ctype == AVRCP_CTYPE_STABLE)
		handle_stable_response(ctx, buffer, buffer_size);
	else if (rcp_hdr->ctype == AVRCP_CTYPE_NOTIFY)
		btwarnx("NOTIFY response unhandled");
	else if (rcp_hdr->ctype == AVRCP_CTYPE_CHANGED)
		handle_change_notification(ctx, buffer, buffer_size);
}

static gboolean
handle_event(GIOChannel *chan, GIOCondition cond, gpointer data)
{
	uint8_t buffer[128];
	struct ctx *ctx = (struct ctx *)data;

	/* check for hangup */
	if (cond & G_IO_HUP) {
		btwarnx("socket hung up");
		return FALSE;
	}

	/* otherwise read the message and handle it */
	ssize_t msgsize = recv(ctx->fd, buffer, sizeof(buffer), 0);
	if (msgsize < 0)
		bterr("could not receive message");

	struct avctp_header *avctphdr = (struct avctp_header *)buffer;
	if (avctp_is_command(avctphdr))
		handle_command(ctx, buffer, msgsize);
	else if (avctp_is_response(avctphdr))
		handle_response(ctx, buffer, msgsize);
	else
		btwarnx("Don't know how to handle packet");

	return TRUE;

}

static int
query_capabilities(struct ctx *ctx)
{
	uint8_t buffer[64] = {0};
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	uint8_t *caps = (uint8_t *)(rcp_hdr + 1);
	enum { packet_len = sizeof(*ctp_hdr) + sizeof(*rcp_hdr) + sizeof(*caps) };

	static_assert(packet_len <= sizeof(buffer), "buffer too smol");

	ctp_hdr->pid = htobe16(0x110e);

	rcp_hdr->ctype = AVRCP_CTYPE_STATUS;
	rcp_hdr->subunit = (0x9 << 3) /* subunit type */ | 0x0 /* subunit id */;
	rcp_hdr->opcode = 0; /* vendor specific */
	rcp_hdr->companyid[0] = 0x00;
	rcp_hdr->companyid[1] = 0x19;
	rcp_hdr->companyid[2] = 0x58;
	rcp_hdr->pdu_id = AVRCP_PDUID_GETCAPABILITIES;
	rcp_hdr->packet_type = 0; /* single unfragmented */
	rcp_hdr->param_len = htobe16(sizeof(*caps));

	*caps = 0x03; /* events supported */

	ssize_t n = send(ctx->fd, buffer, packet_len, 0);
	if (n < 0)
		bterr("send");

	return 0;
}

static void
setup_glib_loop(struct ctx *ctx)
{
	GMainContext *gctx = g_main_context_default();
	GIOChannel *iochan = NULL;

	ctx->main_loop = g_main_loop_new(gctx, FALSE);

	iochan = g_io_channel_unix_new(ctx->fd);
	g_io_channel_set_encoding(iochan, NULL, NULL);
	g_io_channel_set_buffered(iochan, FALSE);

	g_io_add_watch(iochan, G_IO_IN|G_IO_HUP, handle_event, ctx);
}

static void
loop(struct ctx *ctx)
{
	struct sockaddr_l2cap sa = {0}, lsa = {0};

	ctx->fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (ctx->fd < 0)
		bterr("could not create BT socket");

	lsa.l2cap_len = sizeof(lsa);
	lsa.l2cap_family = AF_BLUETOOTH;

	if (bind(ctx->fd, (struct sockaddr *)&lsa, sizeof(lsa)) < 0)
		bterr("could not bind BT socket to local address");

	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	sa.l2cap_psm = SDP_UUID_PROTOCOL_AVCTP;
	bdaddr_copy(&sa.l2cap_bdaddr, &remote);

	if (connect(ctx->fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		bterr("could not connect to AVCTP service");

	setup_glib_loop(ctx);

	query_capabilities(ctx);
	g_main_loop_run(ctx->main_loop);
}

int
main(int argc, char *argv[])
{
	char namebuf[32] = {0};
	struct ctx ctx = {0};

	parseflags(&argc, &argv);

	openlog(getprogname(), LOG_PID|LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "Connecting to BT Address: %s\n",
	       bt_ntoa(&remote, namebuf));

	if (!dflag && daemon(0, 0) < 0)
		bterr("could not daemonise");

	playerctl_init(&ctx);
	loop(&ctx);

	return 0;
}
