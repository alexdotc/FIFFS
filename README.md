It's just a playpen for testing fuse performance and various bottlenecks right now.  As of this
writing, it has stupid permissions, a single directory, and doesn't support links or
unlinking/removing files. I.e. it's only useful for testing various performance things.

# Building and running
```bash
mkdir -p build
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo ..
make
mkdir -p mnt
./tmpfs_fuse -f mnt &>/dev/null &
ls mnt
touch mnt/{1..1000}
ls -fl mnt | wc -l
kill %1
```
