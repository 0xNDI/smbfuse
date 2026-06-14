import argparse
import errno
import os
import stat
import struct
import threading
import time
from dataclasses import dataclass
from getpass import getpass

from fuse import FUSE, FuseOSError, Operations
from impacket import nt_errors
from impacket.examples.utils import parse_target
from impacket.smb3structs import (
    FILE_CREATE,
    FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_OPEN_IF,
    FILE_OVERWRITE,
    FILE_OVERWRITE_IF,
    FILE_SHARE_DELETE,
    FILE_SHARE_READ,
    FILE_SHARE_WRITE,
    SMB2_FILE_END_OF_FILE_INFO,
)
from impacket.smbconnection import SMBConnection


GENERIC_READ = 0x80000000
GENERIC_WRITE = 0x40000000
SHARE_ALL = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE
SMB_ERRNO = {
    nt_errors.STATUS_ACCESS_DENIED: errno.EACCES,
    nt_errors.STATUS_OBJECT_NAME_NOT_FOUND: errno.ENOENT,
    nt_errors.STATUS_OBJECT_PATH_NOT_FOUND: errno.ENOENT,
    nt_errors.STATUS_OBJECT_NAME_COLLISION: errno.EEXIST,
    nt_errors.STATUS_SHARING_VIOLATION: errno.EBUSY,
    nt_errors.STATUS_DIRECTORY_NOT_EMPTY: errno.ENOTEMPTY,
    nt_errors.STATUS_NOT_A_DIRECTORY: errno.ENOTDIR,
    nt_errors.STATUS_FILE_IS_A_DIRECTORY: errno.EISDIR,
    nt_errors.STATUS_OBJECT_PATH_SYNTAX_BAD: errno.ENOENT,
    nt_errors.STATUS_DISK_FULL: errno.ENOSPC,
}


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
        read_only: bool = False,
    ) -> None:
        self.target_name = target_name
        self.target_ip = target_ip or target_name
        self.share = share
        self.auth = auth
        self.port = port
        self.read_only = read_only
        self.remote_root = remote_root.strip("/\\")
        self._mutex = threading.RLock()
        self._handles: dict[int, object] = {}
        self._next_fh = 1
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

    def _raise_fuse_error(self, exc: Exception) -> None:
        get_error_code = getattr(exc, "getErrorCode", None)
        if get_error_code is None:
            raise FuseOSError(errno.EIO) from exc
        raise FuseOSError(SMB_ERRNO.get(get_error_code(), errno.EIO)) from exc

    def _call(self, func, *args, retry: bool = True):
        with self._mutex:
            try:
                return func(*args)
            except FuseOSError:
                raise
            except Exception as exc:
                if not retry:
                    self._raise_fuse_error(exc)
                try:
                    self._connect()
                    return func(*args)
                except FuseOSError:
                    raise
                except Exception as exc:
                    self._raise_fuse_error(exc)

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

    def _check_writable(self) -> None:
        if self.read_only:
            raise FuseOSError(errno.EROFS)

    def _store_handle(self, file_id) -> int:
        fh = self._next_fh
        self._next_fh += 1
        self._handles[fh] = file_id
        return fh

    def _file_id(self, fh):
        try:
            return self._handles[fh]
        except KeyError:
            raise FuseOSError(errno.EBADF)

    def _desired_access(self, flags: int) -> int:
        access_mode = flags & os.O_ACCMODE
        if access_mode == os.O_RDONLY:
            return GENERIC_READ
        if access_mode == os.O_WRONLY:
            return GENERIC_WRITE
        return GENERIC_READ | GENERIC_WRITE

    def _creation_disposition(self, flags: int) -> int:
        create = bool(flags & os.O_CREAT)
        excl = bool(flags & os.O_EXCL)
        trunc = bool(flags & os.O_TRUNC)

        if create and excl:
            return FILE_CREATE
        if create and trunc:
            return FILE_OVERWRITE_IF
        if create:
            return FILE_OPEN_IF
        if trunc:
            return FILE_OVERWRITE
        return FILE_OPEN

    def _open_file(self, path: str, flags: int, disposition: int | None = None) -> int:
        remote = self._remote(path)

        def do_open():
            file_id = self.conn.openFile(
                self.tree_id,
                remote,
                desiredAccess=self._desired_access(flags),
                shareMode=SHARE_ALL,
                creationOption=FILE_NON_DIRECTORY_FILE,
                creationDisposition=disposition if disposition is not None else self._creation_disposition(flags),
            )
            return self._store_handle(file_id)

        return self._call(do_open)

    def getattr(self, path: str, fh=None):
        now = time.time()
        if path == "/":
            mode = 0o555 if self.read_only else 0o755
            return {
                "st_mode": stat.S_IFDIR | mode,
                "st_nlink": 2,
                "st_size": 0,
                "st_ctime": now,
                "st_mtime": now,
                "st_atime": now,
            }

        entry = self._entry(path)
        is_dir = entry.is_directory()
        dir_mode = 0o555 if self.read_only else 0o755
        file_mode = 0o444 if self.read_only else 0o644
        mode = (stat.S_IFDIR | dir_mode) if is_dir else (stat.S_IFREG | file_mode)
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
            self._check_writable()
        return self._open_file(path, flags)

    def create(self, path: str, mode: int, fi=None):
        self._check_writable()
        flags = os.O_RDWR | os.O_CREAT
        return self._open_file(path, flags, FILE_OVERWRITE_IF)

    def lock(self, path: str, fh, cmd, lock):
        return 0

    def read(self, path: str, size: int, offset: int, fh):
        if fh is not None:
            file_id = self._file_id(fh)
            return self._call(
                lambda: self.conn.readFile(self.tree_id, file_id, offset, size),
                retry=False,
            )

        def do_read():
            file_id = self.conn.openFile(
                self.tree_id,
                self._remote(path),
                desiredAccess=GENERIC_READ,
                shareMode=SHARE_ALL,
            )
            try:
                return self.conn.readFile(self.tree_id, file_id, offset, size)
            finally:
                self.conn.closeFile(self.tree_id, file_id)

        return self._call(do_read)

    def write(self, path: str, data: bytes, offset: int, fh):
        self._check_writable()
        file_id = self._file_id(fh)
        self._call(lambda: self.conn.writeFile(self.tree_id, file_id, data, offset), retry=False)
        return len(data)

    def truncate(self, path: str, length: int, fh=None):
        self._check_writable()

        def set_eof(file_id):
            self.conn.setInfo(
                self.tree_id,
                file_id,
                SMB2_FILE_END_OF_FILE_INFO,
                struct.pack("<Q", length),
            )

        if fh is not None:
            self._call(lambda: set_eof(self._file_id(fh)), retry=False)
            return 0

        def do_truncate():
            file_id = self.conn.openFile(
                self.tree_id,
                self._remote(path),
                desiredAccess=GENERIC_WRITE,
                shareMode=SHARE_ALL,
                creationOption=FILE_NON_DIRECTORY_FILE,
                creationDisposition=FILE_OPEN,
            )
            try:
                set_eof(file_id)
            finally:
                self.conn.closeFile(self.tree_id, file_id)

        self._call(do_truncate)
        return 0

    def flush(self, path: str, fh):
        return 0

    def fsync(self, path: str, fdatasync: int, fh):
        return 0

    def release(self, path: str, fh):
        file_id = self._handles.pop(fh, None)
        if file_id is None:
            return 0
        self._call(lambda: self.conn.closeFile(self.tree_id, file_id), retry=False)
        return 0

    def unlink(self, path: str):
        self._check_writable()
        self._call(self.conn.deleteFile, self.share, self._remote(path))
        return 0

    def mkdir(self, path: str, mode: int):
        self._check_writable()
        self._call(self.conn.createDirectory, self.share, self._remote(path))
        return 0

    def rmdir(self, path: str):
        self._check_writable()
        self._call(self.conn.deleteDirectory, self.share, self._remote(path))
        return 0

    def rename(self, old: str, new: str):
        self._check_writable()
        self._call(self.conn.rename, self.share, self._remote(old), self._remote(new))
        return 0

    def statfs(self, path: str):
        return {"f_bsize": 4096, "f_blocks": 1_000_000, "f_bavail": 1_000_000}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="smbfuse",
        description="Mount an SMB share with FUSE.",
    )
    parser.add_argument("target", help="[[domain/]username[:password]@]<targetName or address>")
    parser.add_argument("mountpoint", help="Local mountpoint to create/use")
    parser.add_argument("-share", required=True, help="SMB share name")
    parser.add_argument("-remote-root", default="", help="Remote subdirectory to expose")
    parser.add_argument("-read-only", action="store_true", help="mount read-only and reject local writes")

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
        read_only=args.read_only,
    )
    print(f"Authentication successful for {auth.domain + '/' if auth.domain else ''}{auth.username or 'anonymous'}")
    print(f"Share {args.share} mounted at {args.mountpoint}")
    print("Press Ctrl-C to quit")
    FUSE(
        fs,
        args.mountpoint,
        foreground=True,
        ro=args.read_only,
        nothreads=True,
    )
