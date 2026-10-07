package network

// The selected daemon, not a remote controller's filesystem, is the authority
// for this explicit mode. Socket identity is checked while holding the very same
// /run/lock inode used by local Linux controllers. stdin remains the attached
// admission channel; exec preserves fd 9 through all native mutation scripts.
const nativeDaemonLockScript = `
import fcntl
import http.client
import json
import os
import socket
import stat
import sys
import time

class Engine(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect("/var/run/docker.sock")

path = "/run/lock/stackd-public-network.lock"
fd = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
try:
    observed = os.fstat(fd)
    if not stat.S_ISREG(observed.st_mode):
        raise SystemExit("native network lock must be a regular daemon-host file")
    deadline = time.monotonic() + 15
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            break
        except BlockingIOError:
            if time.monotonic() >= deadline:
                raise SystemExit("timed out acquiring daemon-host native network lock")
            time.sleep(0.05)
    current = os.stat(path, follow_symlinks=False)
    if (current.st_dev, current.st_ino) != (observed.st_dev, observed.st_ino):
        raise SystemExit("daemon-host native network lock inode changed")
    connection = Engine("localhost", timeout=10)
    try:
        connection.request("GET", "/v1.41/info")
        response = connection.getresponse()
        engine = json.load(response)
        if response.status != 200 or engine.get("ID") != os.environ["NATIVE_ENGINE_ID"] or engine.get("OSType") != "linux":
            raise SystemExit("native network helper socket does not identify the selected Linux Engine")
    finally:
        connection.close()
    with open("/proc/sys/kernel/random/boot_id") as boot:
        os.environ["NATIVE_LOCK_IDENTITY"] = boot.read().strip() + " " + str(observed.st_dev) + ":" + str(observed.st_ino)
    if fd != 9:
        os.dup2(fd, 9, inheritable=True)
        os.close(fd)
    else:
        os.set_inheritable(9, True)
    fd = 9
    os.execv("/bin/sh", ["/bin/sh", "-ec", sys.argv[1]])
except BaseException:
    os.close(fd)
    raise
`
