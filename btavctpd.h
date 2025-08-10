#ifndef BTAVCTPD_H
#define BTAVCTPD_H

#include <stdint.h>
#include <inttypes.h>

#include <playerctl.h>

struct ctx {
	int fd; /* l2cap socket */

	uint32_t event_mask; /* registered events by the peer */
	uint8_t status_tid; /* status event transaction id */

	GMainLoop *main_loop;
	PlayerctlPlayerManager *player_manager;
	PlayerctlPlayer *current_player;
};

struct avctp_header {
	uint8_t id;
	uint16_t pid;
} __packed;

static inline uint8_t
avctp_tid(struct avctp_header const *hdr)
{
	return (hdr->id >> 4) & 0xf;
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
	uint8_t params[1];
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

struct avrcp_reg_evt_payload {
	uint8_t evt_id;
	uint8_t rfa[4];
} __packed;

struct avrcp_event_list {
	uint8_t n_evts;
	uint8_t evts[0];
} __packed;

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

enum {
	AVC_PLAY = 0x44,
	AVC_STOP = 0x45,
	AVC_PAUSE = 0x46,
	AVC_NEXT = 0x4b,
	AVC_PREV = 0x4c,

	AVC_PLAY_STATUS_STOPPED = 0x00,
	AVC_PLAY_STATUS_PLAYING,
	AVC_PLAY_STATUS_PAUSED,
	AVC_PLAY_STATUS_FWD_SEEK,
	AVC_PLAY_STATUS_REV_SEEK,
	AVC_PLAY_STATUS_ERROR = 0xff,
};

static inline char const *
event_name(uint8_t const ev)
{
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

	if (ev > (sizeof(evmap) / sizeof(*evmap)))
		return "unknown";

	char const *const n = evmap[ev];
	return n ? n : "unknown";
}

void btwarnx(char const *const fmt, ...);
void playerctl_init(struct ctx *ctx);
void playerctl_play(struct ctx *ctx);
void playerctl_playpause(struct ctx *ctx);
void playerctl_next(struct ctx *ctx);
void playerctl_prev(struct ctx *ctx);
void playerctl_event_registered(struct ctx *ctx, uint8_t tid, uint8_t event_id);
void bt_send_avrcp_change_event(struct ctx *ctx, uint8_t tid, uint8_t evt_id, uint8_t status);
void bt_send_avrcp_interim(struct ctx *ctx, uint8_t tid, uint8_t evt_id, uint8_t status);

#endif /* BTAVCTPD_H */
