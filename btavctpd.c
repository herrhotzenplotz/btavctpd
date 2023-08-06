#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
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

struct avctp_header {
	uint8_t id;
	uint16_t pid;
} __packed;

struct avc_header {
	uint8_t ctype;
	uint8_t subunit;
	uint8_t opcode;
	uint8_t operation;
	uint8_t data_length;
} __packed;

struct avrcp_header {
	uint8_t ctype;
	uint8_t subunit;
	uint8_t opcode;
	uint8_t companyid[3];
	uint8_t pdu_id;
	uint8_t packet_type;
	uint16_t param_len;
} __packed;

struct avrcp_event {
	uint8_t event_id;
	uint8_t params[0];
} __packed;

enum {
	AVRCP_CTYPE_CONTROL = 0x00,
	AVRCP_CTYPE_STATUS = 0x01,
	AVRCP_CTYPE_SPECIFIC_INQUIRY = 0x02,
	AVRCP_CTYPE_NOTIFY = 0x03,
	AVRCP_CTYPE_GENERAL_INQUIRY = 0x04,
	AVRCP_CTYPE_ACCEPTED = 0x09,
	AVRCP_CTYPE_REJECTED = 0x0a,
	AVRCP_CTYPE_STABLE = 0x0c,
	AVRCP_CTYPE_CHANGED = 0x0d,
	AVRCP_CTYPE_INTERIM = 0x0f,
};

enum {
	AVRCP_PDUID_GETCAPABILITIES = 0x10,
	AVRCP_PDUID_REGISTERNOTIFICATION = 0x31,
};

enum {
	AVRCP_OPCODE_VENDOR = 0x00,
	AVRCP_OPCODE_PASSTHRU = 0x7C,
};

enum {
	AVRCP_EVENT_STATUS_CHANGED = 0x01,
	AVRCP_EVENT_TRACK_CHANGED = 0x02,
	AVRCP_EVENT_TRACK_REACHED_END = 0x03,
	AVRCP_EVENT_TRACK_REACHED_START = 0x04,
	AVRCP_EVENT_PLAYBACK_POS_CHANGED = 0x05,
	AVRCP_EVENT_SETTINGS_CHANGED = 0x08,
	AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED = 0x0a,
	AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED = 0x0b,
	AVRCP_EVENT_VOLUME_CHANGED = 0x0d,
};

static char const *const evmap[] = {
	[AVRCP_EVENT_STATUS_CHANGED] = "Status Changed",
	[AVRCP_EVENT_TRACK_CHANGED] = "Track Changed",
	[AVRCP_EVENT_TRACK_REACHED_END] = "Track Reached End",
	[AVRCP_EVENT_TRACK_REACHED_START] = "Track Reached Start",
	[AVRCP_EVENT_PLAYBACK_POS_CHANGED] = "Playback Position Changed",
	[AVRCP_EVENT_SETTINGS_CHANGED] = "Settings Changed",
	[AVRCP_EVENT_AVAILABLE_PLAYERS_CHANGED] = "Available Players Changed",
	[AVRCP_EVENT_ADDRESSED_PLAYER_CHANGED] = "Adressed Players Changed",
	[AVRCP_EVENT_VOLUME_CHANGED] = "Volume Changed",
};

enum {
	AVC_PLAY = 0x44,
	AVC_STOP = 0x45,
	AVC_PAUSE = 0x46,
	AVC_NEXT = 0x4b,
	AVC_PREV = 0x4c,
};

static char const *
event_name(uint8_t const ev)
{
	if (ev > (sizeof(evmap) / sizeof(*evmap)))
		return "unknown";

	char const *const n = evmap[ev];
	return n ? n : "unknown";
}

static inline int
avctp_is_response(struct avctp_header const *hdr)
{
	return !!(hdr->id & 0x2);
}

static inline int
avctp_is_command(struct avctp_header const *hdr)
{
	return (hdr->id & 0x2) == 0;
}

static inline int
avctp_is_singleframe(struct avctp_header const *hdr)
{
	return (hdr->id & 0xC) == 0;
}

static bdaddr_t remote = {0};    /* Address of the remote side */
static int dflag = 0;            /* -d was specified (no daemon) */

/* print a usage message */
static void
usage(void)
{
	fprintf(stderr, "usage: %s [-d] -h address\n", getprogname());
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

static void
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

	while ((ch = getopt_long(*argc, *argv, "+dh:", options, NULL)) != -1) {
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
reply_passthru(int fd, uint8_t const ctype, uint8_t const operation)
{
	uint8_t buffer[8] = {0};
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avc_header *avc = (struct avc_header *)(ctp_hdr + 1);
	enum { pkt_len = sizeof(*ctp_hdr) + sizeof(*avc) };

	static_assert(pkt_len <= sizeof(buffer), "Buffer too smol");

	ctp_hdr->id = 0x02;
	ctp_hdr->pid = htobe16(0x110e);

	avc->ctype = ctype;
	avc->subunit = (0x9 << 3) /* subunit type */ | 0x0 /* subunit id */;
        avc->opcode = AVRCP_OPCODE_PASSTHRU;
        avc->operation = operation;
        avc->data_length = 0;

	size_t rc = send(fd, buffer, pkt_len, 0);
	if (rc < 0)
		bterr("send failed");
}

static void
handle_passthru(int fd, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avc_header *avc = (struct avc_header *)(ctp_hdr + 1);

	/* Button was released */
	if (avc->operation & 0x80) {
		syslog(LOG_INFO, "Button release event");
		return;
	}

	switch (avc->operation & 0x7F) {
	case AVC_PLAY:
		syslog(LOG_INFO, "Received Play Event");
		system("xdotool key XF86AudioPlay");
		goto ack;
	case AVC_PAUSE:
		syslog(LOG_INFO, "Received Pause Event");
		system("xdotool key XF86AudioPause");
		goto ack;
	case AVC_NEXT:
		syslog(LOG_INFO, "Received Next Event");
		system("xdotool key XF86AudioNext");
		goto ack;
	case AVC_PREV:
		syslog(LOG_INFO, "Received Previous Event");
		system("xdotool key XF86AudioPrev");
		goto ack;
	case AVC_STOP:
		syslog(LOG_INFO, "Received Stop Event");
		puts("Stopping");
		/* FALLTHRU */
	ack:
		reply_passthru(fd, AVRCP_CTYPE_ACCEPTED, avc->operation);
		break;
	default:
		btwarnx("rejecting unknown operation: 0x%"PRIx8,
		        avc->operation & 0x7F);
		reply_passthru(fd, AVRCP_CTYPE_REJECTED, avc->operation);
		break;
	}
}

static void
handle_command(int fd, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);

	if (rcp_hdr->ctype == AVRCP_CTYPE_CONTROL) {
		if (rcp_hdr->opcode == AVRCP_OPCODE_PASSTHRU)
			handle_passthru(fd, buffer, buffer_size);
		else
			btwarnx("unhandled control command: 0x%"PRIx8,
			        rcp_hdr->opcode);
	} else {
		btwarnx("Unhandled command with ctype 0x%"PRIx8,
		        rcp_hdr->ctype);
	}
}

static void
register_notifications(int const fd, uint8_t const evt_id)
{
	struct reg_evt_payload {
		uint8_t evt_id;
		uint8_t rfa[4];
	} __packed;

	uint8_t buffer[64] = {0};
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	struct reg_evt_payload *rep = (struct reg_evt_payload *)(rcp_hdr + 1);
	enum { packet_len = sizeof(*ctp_hdr) + sizeof(*rcp_hdr) + sizeof(*rep) };

	static_assert(packet_len <= sizeof(buffer), "buffer too smol");

	ctp_hdr->pid = htobe16(0x110e);

	rcp_hdr->ctype = AVRCP_CTYPE_NOTIFY;
	rcp_hdr->subunit = (0x9 << 3) /* subunit type */ | 0x0 /* subunit id */;
	rcp_hdr->opcode = 0; /* vendor specific */
	rcp_hdr->companyid[0] = 0x00;
	rcp_hdr->companyid[1] = 0x19;
	rcp_hdr->companyid[2] = 0x58;
	rcp_hdr->pdu_id = AVRCP_PDUID_REGISTERNOTIFICATION;
	rcp_hdr->packet_type = 0; /* single unfragmented */
	rcp_hdr->param_len = htobe16(sizeof(*rep));

	rep->evt_id = evt_id;

	ssize_t n = send(fd, buffer, packet_len, 0);
	if (n < 0)
		bterr("send");
}

static void
handle_supported_event(int fd, uint8_t evt)
{
	syslog(LOG_INFO, "Register notifications for event %s",
	       event_name(evt));
	register_notifications(fd, evt);
}

static void
handle_stable_response(int fd, uint8_t const *buffer, size_t const buffer_size)
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
			struct evt_list {
				uint8_t n_evts;
				uint8_t evts[0];
			} __packed *evt_list;

			evt_list = (struct evt_list *)(caps + 1);

			for (uint8_t i = 0; i < evt_list->n_evts; ++i) {
				handle_supported_event(fd, evt_list->evts[i]);
			}
		}
	} break;
	case AVRCP_PDUID_REGISTERNOTIFICATION: {
		btwarnx("Stable RegisterNotification response");
	} break;
	}
}

static void
handle_change_notification(int fd, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);
	struct change_payload {
		uint8_t evt_id;
		uint8_t payload[0];
	} __packed;

	struct change_payload *c_payload = (struct change_payload *)(rcp_hdr + 1);

	switch (c_payload->evt_id) {
	case AVRCP_EVENT_VOLUME_CHANGED: {
		uint8_t vol = c_payload->payload[0] & 0x7F; /* RFA bit masked off */
		double perc = ((double)(vol) / (double)(0x7F)) * 100.0;
		syslog(LOG_INFO, "Volume changed to %lf%%", perc);
	} break;
	default:
		btwarnx("Unhandled change event");
		break;
	}
}

static void
handle_response(int fd, uint8_t const *buffer, size_t const buffer_size)
{
	struct avctp_header *ctp_hdr = (struct avctp_header *)(buffer);
	struct avrcp_header *rcp_hdr = (struct avrcp_header *)(ctp_hdr + 1);

	if (rcp_hdr->ctype == AVRCP_CTYPE_STABLE)
		handle_stable_response(fd, buffer, buffer_size);
	else if (rcp_hdr->ctype == AVRCP_CTYPE_NOTIFY)
		btwarnx("NOTIFY response unhandled");
	else if (rcp_hdr->ctype == AVRCP_CTYPE_CHANGED)
		handle_change_notification(fd, buffer, buffer_size);
}

static void
handle_event(int fd)
{
	uint8_t buffer[128];

	ssize_t msgsize = recv(fd, buffer, sizeof(buffer), 0);
	if (msgsize < 0)
		bterr("could not receive message");

	struct avctp_header *avctphdr = (struct avctp_header *)buffer;
	if (avctp_is_command(avctphdr))
		handle_command(fd, buffer, msgsize);
	else if (avctp_is_response(avctphdr))
		handle_response(fd, buffer, msgsize);
	else
		btwarnx("Don't know how to handle packet");

}

static int
query_capabilities(int fd)
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

	ssize_t n = send(fd, buffer, packet_len, 0);
	if (n < 0)
		bterr("send");

	return 0;
}

static void
loop(void)
{
	int fd;
	struct sockaddr_l2cap sa = {0}, lsa = {0};

	fd = socket(PF_BLUETOOTH, SOCK_SEQPACKET, BLUETOOTH_PROTO_L2CAP);
	if (fd < 0)
		bterr("could not create BT socket");

	lsa.l2cap_len = sizeof(lsa);
	lsa.l2cap_family = AF_BLUETOOTH;

	if (bind(fd, (struct sockaddr *)&lsa, sizeof(lsa)) < 0)
		bterr("could not bind BT socket to local address");

	sa.l2cap_len = sizeof(sa);
	sa.l2cap_family = AF_BLUETOOTH;
	sa.l2cap_psm = SDP_UUID_PROTOCOL_AVCTP;
	bdaddr_copy(&sa.l2cap_bdaddr, &remote);

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
		bterr("could not connect to AVCTP service");

	if (!dflag && daemon(0, 0) < 0)
		bterr("could not daemonise");

	query_capabilities(fd);

	/* Poll loop */
	{
		for (;;) {
			int rc;
			struct pollfd pfd = {
				.fd = fd,
				.events = POLLIN|POLLHUP,
				.revents = 0,
			};

			rc = poll(&pfd, 1, -1);
			if (rc < 0)
				bterr("poll error");

			if (pfd.revents & POLLIN) {
				handle_event(fd);
			}
		}
	}

	close(fd);
}

int
main(int argc, char *argv[])
{
	char namebuf[32] = {0};

	parseflags(&argc, &argv);

	openlog(getprogname(), LOG_PID|LOG_PERROR, LOG_DAEMON);
	syslog(LOG_INFO, "Connecting to BT Address: %s\n",
	       bt_ntoa(&remote, namebuf));

	loop();

	return 0;
}
