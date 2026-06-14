# smbfuse

Mount SMB shares read-only through FUSE using Impacket-style authentication.

`smbfuse` is for cases where you want normal filesystem tools (`ls`, `find`,
`grep`, `cp`, editors, forensic tools) against an SMB share, while keeping the
credential flexibility of Impacket's SMB tooling.

## Install

System dependencies on Debian/Kali/Ubuntu:

```bash
sudo apt install fuse3 libfuse2
```

`libfuse2` is required by `fusepy`; `fuse3` provides userland FUSE tools such as
`fusermount3` for cleanup.

From a git repository:

```bash
uv tool install git+https://github.com/0xNDI/smbfuse
```

From a local checkout:

```bash
uv tool install .
```

## Usage

The target syntax intentionally follows `smbclient.py`:

```text
[[domain/]username[:password]@]<targetName or address>
```

NT hash:

```bash
smbfuse example.local/backup-reader@dc01.example.local backups \
  -share Backups \
  -hashes :0123456789abcdef0123456789abcdef
```

Plaintext password:

```bash
smbfuse example.local/jordan:'CorrectHorseBatteryStaple1!'@dc01.example.local mnt -share Documents
```

Kerberos ccache:

```bash
KRB5CCNAME=./jordan.ccache smbfuse example.local/jordan@dc01.example.local mnt -share C$ -k -no-pass
```

Or pass the ccache directly:

```bash
smbfuse example.local/jordan@dc01.example.local mnt -share C$ -ccache ./jordan.ccache
```

Kerberos AES key:

```bash
smbfuse example.local/jordan@dc01.example.local mnt -share C$ \
  -aesKey 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Connection options match Impacket names where applicable:

```text
-hashes LMHASH:NTHASH
-no-pass
-k
-ccache file
-aesKey hexkey
-dc-ip ip
-target-ip ip
-port port
```

`-ccache` and `-aesKey` imply Kerberos authentication and do not prompt for a
password.

Since `smbfuse` runs in the foreground, stop it with `Ctrl-C` when you are done.
If the mountpoint is left behind after an interrupted session, unmount it with:

```bash
fusermount -u mnt
```
