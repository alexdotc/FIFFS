#!/usr/bin/env python3

import argparse
import os
import subprocess
from pathlib import Path

fiffs_path = '/dev/shm/fiffs'
args: argparse.Namespace

class MountFIFFS:
    def __init__(self, path=fiffs_path, binary: str = './tmpfs_fuse'):
        os.makedirs(path, exist_ok=True)
        self._proc = subprocess.Popen([binary, '-f', path], stdout=subprocess.PIPE)

    def __del__(self):
        self._proc.terminate()

def run_mdtest(path: str, create_only: bool = False, N: int = 100000) -> str:
    if not os.path.exists(path):
        os.makedirs(path, exist_ok=True)
    args = ["mpirun", "-n", args.mpi, "mdtest", "-n", str(N), "-F", "-d", path]
    if create_only:
        args = args[0:4] + ['-C', '-T', '-E'] + args[4:]

    output = subprocess.run(args, capture_output=True).stdout.decode('utf-8')
    times = []
    for line in output.splitlines():
        if " : " in line:
            times.append(line.split()[-2])

    return ",".join(times)

def parse_args() -> argparse.Namespace:
    argp = argparse.ArgumentParser(description="Update FI accounts based on transition and hire data from IT Filemaker Database")
    argp.add_argument('-p', '--mpi', default=1, help="Number of MPI processes to launch [1]")
    return argp.parse_args()
    
args = parse_args()
mount = MountFIFFS()
print("fs,fcreation,fstat,fread,fremoval,tcreation,tremoval")
print("fiffs," + run_mdtest(fiffs_path, create_only=True, N=100000))
print("nvme," + run_mdtest('/tmp/fiffs', N=100000))
print("shmem," + run_mdtest('/dev/shm/tmp/fiffs', N=1000000))
print("gpfs," + run_mdtest(os.path.join(Path.home(), 'tmp', 'fiffs'), N=10000))
print("ceph," + run_mdtest(os.path.join(Path.home(), 'ceph', 'tmp', 'fiffs'), N=10000))
