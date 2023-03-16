It's just a playpen for testing fuse performance and various bottlenecks right now.  As of this
writing, it has stupid permissions, a single directory, and doesn't support links or
unlinking/removing files. I.e. it's only useful for testing various performance things.

# Building and running
```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make

./tmpfs_fuse -f /path/to/mnt &>/dev/null
touch /path/to/mnt/{0..100}
```
