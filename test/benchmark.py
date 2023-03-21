#!/usr/bin/env python3
# dnf install libguestfs-tools fuse3

import argparse
import os
import subprocess
import sys
from pathlib import Path

fiffs_path = '/dev/shm/fiffs'
guest_path = '/dev/shm/guest'
guest_img = '/dev/shm/guest.img'

input_args: argparse.Namespace

class MountFIFFS:
    def __init__(self, path=fiffs_path, binary: str = './tmpfs_fuse'):
        os.makedirs(path, exist_ok=True)
        self._proc = subprocess.Popen([binary, '-f', path], stdout=subprocess.PIPE)

    def __del__(self):
        self._proc.terminate()


class MountGuest:
    def __init__(self, path=guest_path, img=guest_img):
        self.img = img
        self.path = path
        os.makedirs(path, exist_ok=True)
        subprocess.run(['dd', 'if=/dev/zero', f'of={img}', 'bs=1M', 'count=500'], capture_output=True)
        subprocess.run(['mkfs.ext2', img], capture_output=True)
        subprocess.run(['guestmount', '-a', img, '-m', '/dev/sda', path], capture_output=True)

    def __del__(self):
        subprocess.run(['fusermount', '-u', self.path])
        os.remove(self.img)


def run_mdtest(path: str, create_only: bool = False, N: int = 100000) -> str:
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
    args = ["mpirun", "-n", str(input_args.mpi), "mdtest", "-n", str(N), "-F", "-d", path]
    if create_only:
        args = args[0:4] + ['-C', '-T', '-E'] + args[4:]

    try:
        cp = subprocess.run(args, capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"\"{' '.join(e.cmd)}\" exited with rc {e.returncode}:\n {e.stderr.decode('utf-8')}", file=sys.stderr)
        raise

    output = cp.stdout.decode('utf-8')
    times = []
    for line in output.splitlines():
        if " : " in line:
            times.append(line.split()[-2])

    return ",".join(times)

def parse_args() -> argparse.Namespace:
    argp = argparse.ArgumentParser(description="Benchmark metadata IOPs for filesystems")
    argp.add_argument('-p', '--mpi', default=1, type=int, help="Number of MPI processes to launch [1]")
    return argp.parse_args()

input_args = parse_args()
fiffs_mount = MountFIFFS()
guest_mount = MountGuest()
print("fs,fcreation,fstat,fread,fremoval,tcreation,tremoval")
print("fiffs," + run_mdtest(fiffs_path, create_only=True, N=100000))
print("nvme," + run_mdtest('/tmp/fiffs', N=100000))
print("shmem," + run_mdtest('/dev/shm/tmp/fiffs', N=1000000))
print("gpfs," + run_mdtest(os.path.join(Path.home(), 'tmp', 'fiffs'), N=10000))
print("ceph," + run_mdtest(os.path.join(Path.home(), 'ceph', 'tmp', 'fiffs'), N=10000))
print("guest+ext2," + run_mdtest('/dev/shm/guest', N=10000))
