# A hacky Bluetooth AVRCP Profile daemon for FreeBSD

This thing allows you to remote control media players on your workstation through Bluetooth.

When given `-p` this uses the playerctl library to control media player implementing the mpris interface.
Otherwise the daemon emits key presses through `xdotool`.

## Build

Run make, darnit.

## Usage

```console
$ ./btavctpd [-d] [-p] -h <bthostname>
```

Also, there's a manual page that you can read:

```console
$ man ./btavctpd.8
```

If you use mpv I suggest you install `multimedia/mpv-mpris` which makes mpv remote-controllable through btavctpd.
