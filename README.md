# zsync

zsync keeps clipboards in sync across macOS, Linux, and Windows. It connects
peers directly over TCP or through a `zsyncd` relay. It also works on headless
machines, where clipboard data is stored in files.

**Relay mode encrypts clipboard contents end to end.** Clients encrypt before
sending; the relay forwards ciphertext without decrypting it.

## Build

Requires a stable Rust toolchain.

```sh
cargo build --release
```

The `zsync` and `zsyncd` binaries are placed in `target/release/`.

## Quick start: direct connection

Run the daemon on both machines, then connect from one to the other's address:

```sh
zsync daemon
zsync connect 192.168.1.10
zsync status
```

The default TCP port is `43721`; use `host:port` and set `ZSYNC_PORT` on the
listening machine to change it. Direct TCP is unencrypted, so use it only on
trusted networks.

## Through a relay

Run `zsyncd` on a reachable server and create a group:

```sh
zsyncd daemon
zsyncd group create --domain relay.example.com
```

The create command prints a `zsync://` URI once. On each client, start the
daemon with `zsync daemon` and connect using that URI:

```sh
zsync connect 'zsync://...'
```

Keep the URI private: it contains the group key. `zsyncd` prints it when the
group is created but does not store the key. Clients use the shared key to
encrypt and decrypt clipboard payloads with XChaCha20-Poly1305. The relay can
see connection details such as group ID, device ID, hostname, and IP address.

## Clipboard commands

```sh
echo hello | zsync copy   # short form: zsync c
zsync paste              # short form: zsync p
zsync paste --content    # print bytes, including on headless machines
zsync disconnect         # remove all saved peers
zsync daemon stop
```

Files and images pasted with `zsync paste` are written to the current
directory. For text, `zsync paste --path` prints the stored clipboard path.
Clipboard payloads are limited to 10 MiB. On Linux, native clipboard access
uses Wayland (`wl-copy`/`wl-paste`) or X11 (`xclip`/`xsel`) when available.

Run `zsync --help` or `zsyncd --help` for the full command list.
