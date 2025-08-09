#include "btavctpd.h"
#include <playerctl.h>

static void
on_player_appeared(PlayerctlPlayerManager *mgr,
                   PlayerctlPlayerName *pname,
                   gpointer *userdata)
{
	struct ctx *ctx = (struct ctx *)userdata;
	btwarnx("Player appeared: %s\n", pname->name);
}

static void
on_player_vanished(PlayerctlPlayerManager *mgr,
                   PlayerctlPlayerName *pname,
                   gpointer *userdata)
{
	struct ctx *ctx = (struct ctx *)userdata;
	btwarnx("Player vanished: %s\n", pname->name);
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

	g_signal_connect(ctx->player_manager, "name-vanished",
	                 G_CALLBACK(on_player_vanished),
	                 ctx);
}
