import argparse
import errno
import os
import stat
import threading
import time
from dataclasses import dataclass
from getpass import getpass

from fuse import FUSE, FuseOSError, Operations
from impacket.examples.utils import parse_target
from impacket.smbconnection import SMBConnection


GENERIC_READ = 0x80000000


@dataclass(frozen=True)
class AuthConfig:
    domain: str
    username: str
    password: str
    lmhash: str
    nthash: str
    kerberos: bool
    ccache: str | None
    aes_key: str
    kdc_host: str | None


class SMBFuse(Operations):
    def __init__(
        self,
        target_name: str,
        share: str,
        auth: AuthConfig,
        remote_root: str = "",
        target_ip: str | None = None,
        port: int = 445,
    ) -> None:
        self.target_name = target_name
        self.target_ip = target_ip or target_name
        self.share = share
        self.auth = auth
        self.port = port
        self.remote_root = remote_root.strip("/\\")
        self._mutex = threading.RLock()
        self.connected = False
        self._connect()

    def _connect(self) -> None:
        if self.auth.ccache:
            os.environ["KRB5CCNAME"] = self.auth.ccache

        self.conn = SMBConnection(
            self.target_name,
            self.target_ip,
            sess_port=self.port,
        )
        if self.auth.kerberos:
            self.conn.kerberosLogin(
                self.auth.username,
                self.auth.password,
                self.auth.domain,
                lmhash=self.auth.lmhash,
                nthash=self.auth.nthash,
                aesKey=self.auth.aes_key,
                kdcHost=self.auth.kdc_host,
                useCache=True,
            )
        else:
            self.conn.login(
                self.auth.username,
                self.auth.password,
                domain=self.auth.domain,
                lmhash=self.auth.lmhash,
                nthash=self.auth.nthash,
            )
        self.tree_id = self.conn.connectTree(self.share)
        self.connected = True

    def _call(self, func, *args):
        with self._mutex:
            try:
                return func(*args)
            except FuseOSError:
                raise
            except Exception:
                try:
                    self._connect()
                    return func(*args)
                except FuseOSError:
                    raise
                except Exception as exc:
                    raise FuseOSError(errno.EIO) from exc

    def _remote(self, path: str) -> str:
        path = path.strip("/")
        if self.remote_root and path:
            return self.remote_root + "/" + path
        if self.remote_root:
            return self.remote_root
        return path

    def _list(self, remote: str):
        pattern = (remote.rstrip("/") + "/*") if remote else "*"
        return self._call(self.conn.listPath, self.share, pattern)

    def _entry(self, path: str):
        if path == "/":
            return None
        parent, name = os.path.split(path.strip("/"))
        for entry in self._list(self._remote(parent)):
            if entry.get_longname() == name:
                return entry
        raise FuseOSError(errno.ENOENT)

    def getattr(self, path: str, fh=None):
        now = time.time()
        if path == "/":
            return {
                "st_mode": stat.S_IFDIR | 0o555,
                "st_nlink": 2,
                "st_size": 0,
                "st_ctime": now,
                "st_mtime": now,
                "st_atime": now,
            }

        entry = self._entry(path)
        is_dir = entry.is_directory()
        mode = (stat.S_IFDIR | 0o555) if is_dir else (stat.S_IFREG | 0o444)
        return {
            "st_mode": mode,
            "st_nlink": 2 if is_dir else 1,
            "st_size": 0 if is_dir else entry.get_filesize(),
            "st_ctime": now,
            "st_mtime": now,
            "st_atime": now,
        }

    def readdir(self, path: str, fh):
        entries = [".", ".."]
        for entry in self._list(self._remote(path)):
            name = entry.get_longname()
            if name not in (".", ".."):
                entries.append(name)
        return entries

    def open(self, path: str, flags: int):
        if flags & (os.O_WRONLY | os.O_RDWR):
            raise FuseOSError(errno.EROFS)
        return 0

    def lock(self, path: str, fh, cmd, lock):
        return 0

    def read(self, path: str, size: int, offset: int, fh):
        remote = self._remote(path)

        def do_read():
            file_id = self.conn.openFile(
                self.tree_id,
                remote,
                desiredAccess=GENERIC_READ,
                shareMode=0x7,
            )
            try:
                return self.conn.readFile(self.tree_id, file_id, offset, size)
            finally:
                self.conn.closeFile(self.tree_id, file_id)

        return self._call(do_read)

    def statfs(self, path: str):
        return {"f_bsize": 4096, "f_blocks": 1_000_000, "f_bavail": 1_000_000}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smbfuse",
        description="Mount an SMB share read-only with FUSE.",
    )
    parser.add_argument("target", help="[[domain/]username[:password]@]<targetName or address>")
    parser.add_argument("mountpoint", help="Local mountpoint to create/use")
    parser.add_argument("-share", required=True, help="SMB share name")
    parser.add_argument("-remote-root", default="", help="Remote subdirectory to expose")

    auth = parser.add_argument_group("authentication")
    auth.add_argument("-hashes", metavar="LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH")
    auth.add_argument("-no-pass", action="store_true", help="don't ask for password (useful for -k)")
    auth.add_argument("-k", action="store_true", help="Use Kerberos authentication")
    auth.add_argument("-ccache", metavar="file", help="Kerberos ccache file to use instead of KRB5CCNAME")
    auth.add_argument("-aesKey", metavar="hex key", default="", help="AES key for Kerberos Authentication")

    connection = parser.add_argument_group("connection")
    connection.add_argument("-dc-ip", metavar="ip address", help="IP Address of the domain controller")
    connection.add_argument("-target-ip", metavar="ip address", help="IP Address of the target machine")
    connection.add_argument("-port", metavar="destination port", type=int, default=445, help="Destination SMB port")
    return parser


def parse_hashes(value: str | None) -> tuple[str, str]:
    if not value:
        return "", ""
    if ":" not in value:
        return "", value
    return tuple(value.split(":", 1))


def prompt_for_password(username: str, password: str, hashes: str | None, no_pass: bool, kerberos: bool) -> str:
    if password or hashes or no_pass or kerberos:
        return password
    return getpass(f"Password for {username}: ")


def parse_auth(args: argparse.Namespace) -> tuple[AuthConfig, str]:
    domain, username, password, target_name = parse_target(args.target)
    kerberos = args.k or bool(args.ccache or args.aesKey)
    password = prompt_for_password(username, password, args.hashes, args.no_pass, kerberos)
    lmhash, nthash = parse_hashes(args.hashes)
    return (
        AuthConfig(
            domain=domain,
            username=username,
            password=password,
            lmhash=lmhash,
            nthash=nthash,
            kerberos=kerberos,
            ccache=args.ccache,
            aes_key=args.aesKey,
            kdc_host=args.dc_ip,
        ),
        target_name,
    )


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    auth, target_name = parse_auth(args)
    os.makedirs(args.mountpoint, exist_ok=True)
    fs = SMBFuse(
        target_name,
        args.share,
        auth,
        remote_root=args.remote_root,
        target_ip=args.target_ip,
        port=args.port,
    )
    print(f"Authentication successful for {auth.domain + '/' if auth.domain else ''}{auth.username or 'anonymous'}")
    print(f"Share {args.share} mounted at {args.mountpoint}")
    print("Press Ctrl-C to quit")
    FUSE(
        fs,
        args.mountpoint,
        foreground=True,
        ro=True,
        nothreads=True,
    )
