#include "btavctpd.h"
#include <playerctl.h>

static char const *
player_get_name(PlayerctlPlayer const *p)
{
	GValue v = G_VALUE_INIT;

	g_object_get_property(G_OBJECT(p), "player-name", &v);
	return g_value_get_string(&v);
}

static PlayerctlPlaybackStatus
player_get_status(PlayerctlPlayer const *p)
{
	GValue v = G_VALUE_INIT;

	g_object_get_property(G_OBJECT(p), "playback-status", &v);
	return (PlayerctlPlaybackStatus) g_value_get_enum(&v);
}

static uint8_t
playerctl_status_to_avc(PlayerctlPlaybackStatus s)
{
	static uint8_t mapping[] = {
		[PLAYERCTL_PLAYBACK_STATUS_PLAYING] = AVC_PLAY,
		[PLAYERCTL_PLAYBACK_STATUS_PAUSED] = AVC_PAUSE,
		[PLAYERCTL_PLAYBACK_STATUS_STOPPED] = AVC_STOP,
	};

	return mapping[s];
}

static void
notify_player_status_changed(struct ctx *ctx, PlayerctlPlaybackStatus s)
{
}

static void
on_player_status_changed(PlayerctlPlayer *p,
                         PlayerctlPlaybackStatus status,
                         gpointer userdata)
{
	struct ctx *ctx = (struct ctx *)userdata;
	if (p != ctx->current_player)
		return;

	btwarnx("player status of %s changed\n", player_get_name(p));
}

static void
set_current_player(struct ctx *ctx, PlayerctlPlayer *p)
{
	btwarnx("Player elected to default player: %s\n", player_get_name(p));
	ctx->current_player = p;

	/* hook signals */
	g_signal_connect(p, "playback-status",
	                 G_CALLBACK(on_player_status_changed), ctx);

	/* notify the peer of a player appearing */
	notify_player_status_changed(ctx, player_get_status(p));
}

static void
on_player_appeared(PlayerctlPlayerManager *mgr,
                   PlayerctlPlayerName *pname,
                   gpointer userdata)
{
	struct ctx *ctx = (struct ctx *)userdata;
	PlayerctlPlayer *p;
	GError *error = NULL;

	btwarnx("Player appeared: %s\n", pname->name);
	p = playerctl_player_new_from_name(pname, &error);

	if (error != NULL) {
		btwarnx("Failed to connect to player: %s\n",
		        error->message);
		g_error_free(error);
		return;
	}

	playerctl_player_manager_manage_player(mgr, p);

	if (ctx->current_player == NULL)
		set_current_player(ctx, p);
}

static void
on_player_vanished(PlayerctlPlayerManager *mgr,
                   PlayerctlPlayer *p,
                   gpointer userdata)
{
	struct ctx *ctx = (struct ctx *)userdata;

	if (ctx->current_player == p) {
		/* TODO: elect new player if there is one */
		btwarnx("Default player vanished: %s\n", player_get_name(p));
		ctx->current_player = NULL;
	}
}

void
playerctl_init(struct ctx *ctx)
{
	GError *error = NULL;
	GList *players = NULL;

	ctx->player_manager = playerctl_player_manager_new(&error);
	if (error != NULL) {
		btwarnx("failed to create player manager: %s\n",
		        error->message);
		g_error_free(error);
		exit(EXIT_FAILURE);
	}

	g_signal_connect(ctx->player_manager, "name-appeared",
	                 G_CALLBACK(on_player_appeared),
	                 ctx);

	g_signal_connect(ctx->player_manager, "player-vanished",
	                 G_CALLBACK(on_player_vanished),
	                 ctx);
}
