# A hacky Bluetooth AVRCP Profile daemon for FreeBSD

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
