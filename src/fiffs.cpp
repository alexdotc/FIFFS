/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
                2023       Robert Blackwell <rblackwell@flatironinstitute.org>

  This program can be distributed under the terms of the GNU GPLv3.
*/

#define FUSE_USE_VERSION 33

#include <cassert>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <list>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <fuse3/fuse_lowlevel.h>

namespace fiffs {
using std::string;
using std::unordered_map;
using std::vector;

static uid_t uid = 0;
static int fiffs_debug = 0;

struct Inode {
    typedef enum { DIR, FILE } type;
    string name;
    string data;
    std::list<int> dir_children;
    std::list<int> file_children;

    struct stat st {
        .st_ino = (ino_t)-1, .st_nlink = 1, .st_mode = S_IFREG | 0666, .st_uid = uid, .st_gid = uid, .st_size = 0,
    };

    Inode() = default;
    Inode(const string &name_, type T) : name(name_) {
        clock_gettime(CLOCK_REALTIME, &st.st_ctim);
        st.st_atim = st.st_mtim = st.st_ctim;
    }

    size_t namelength() const { return name.length(); }
    size_t size() const { return data.size(); }
    char *cbuf() { return const_cast<char *>(data.data()); }
};

namespace FS {
static vector<Inode> inodes{{}, {Inode("", Inode::DIR)}};
static unordered_map<string, int> name_to_inode;
}; // namespace FS

inline void debug_printf(const char *__restrict format, ...) {
    if (fiffs_debug) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        va_end(args);
    }
}

static int fiffs_stat(fuse_ino_t ino, struct stat *stbuf) {
    stbuf->st_ino = ino;
    debug_printf("fiffs_stat %d\n", ino);

    if (ino == 1) {
        memset(stbuf, 0, sizeof(*stbuf));
        stbuf->st_uid = stbuf->st_gid = uid;
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    } else if (ino > FS::inodes.size())
        return -1;

    *stbuf = FS::inodes[ino].st;

    return 0;
}

static void fiffs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    debug_printf("fiffs_getattr %ld\n", ino);

    struct stat stbuf;
    if (fiffs_stat(ino, &stbuf) == -1)
        fuse_reply_err(req, ENOENT);
    else
        fuse_reply_attr(req, &stbuf, 1.0);
}

static void fiffs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    debug_printf("fiffs_lookup %s\n", name);

    if (parent != 1)
        fuse_reply_err(req, ENOENT);
    else {
        try {
            struct fuse_entry_param e;
            memset(&e, 0, sizeof(e));
            int ino = FS::name_to_inode.at(string(name));

            e.ino = ino;
            e.attr_timeout = 1.0;
            e.entry_timeout = 1.0;
            fiffs_stat(e.ino, &e.attr);

            fuse_reply_entry(req, &e);
            return;
        } catch (...) {
            fuse_reply_err(req, ENOENT);
        }
    }
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize) {
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off, std::min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

static void fiffs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    debug_printf("fiffs_readdir\n");

    if (ino != 1)
        fuse_reply_err(req, ENOTDIR);
    else {
        size_t bufsize;

        std::vector<int> entry_sizes(FS::inodes.size());
        entry_sizes[0] = fuse_add_direntry(req, NULL, 0, ".", NULL, 0);
        entry_sizes[1] = fuse_add_direntry(req, NULL, 0, "..", NULL, 0);

        bufsize = entry_sizes[0] + entry_sizes[1];
        for (int i = 2; i < FS::inodes.size(); ++i) {
            entry_sizes[i] = fuse_add_direntry(req, NULL, 0, FS::inodes[i].name.c_str(), NULL, 0);
            bufsize += entry_sizes[i];
        }

        struct stat stbuf;
        memset(&stbuf, 0, sizeof(stbuf));
        stbuf.st_ino = 1;
        std::vector<char> buf(bufsize);

        int offset = 0;
        fuse_add_direntry(req, buf.data(), entry_sizes[0], ".", &stbuf, offset + entry_sizes[0]);
        offset += entry_sizes[0];
        fuse_add_direntry(req, buf.data() + offset, entry_sizes[1], "..", &stbuf, offset + entry_sizes[1]);
        offset += entry_sizes[1];
        for (int i = 2; i < FS::inodes.size(); ++i) {
            stbuf.st_ino = i;
            const auto &e_size = entry_sizes[i];
            fuse_add_direntry(req, buf.data() + offset, e_size, FS::inodes[i].name.c_str(), &stbuf, offset + e_size);
            offset += e_size;
        }

        reply_buf_limited(req, buf.data(), bufsize, off, size);
    }
}

static void fiffs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    debug_printf("fiffs_open\n");
    if (ino < 2)
        fuse_reply_err(req, EISDIR);
    else
        fuse_reply_open(req, fi);
}

static void fiffs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    struct fuse_bufvec buf = FUSE_BUFVEC_INIT(size);

    const off_t bufsize = FS::inodes[ino].data.size();
    const off_t ret_size = std::min(bufsize - off, off_t(size));
    buf.buf[0].mem = (char *)FS::inodes[ino].cbuf() + off;
    buf.buf[0].size = ret_size;
    debug_printf("fiffs_read %ld %ld %ld\n", off, size, ret_size);
    fuse_reply_data(req, &buf, FUSE_BUF_SPLICE_MOVE);
}

static void fiffs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev) {
    debug_printf("fiffs_mknod %s %ld\n", name, parent);

    if (parent == 1 && S_ISREG(mode)) {
        FS::inodes.push_back(Inode(name, Inode::FILE));
        int ino = FS::inodes.size() - 1;
        fuse_entry_param e;
        e.attr = FS::inodes.back().st;
        FS::inodes.back().st.st_ino = e.ino = e.attr.st_ino = ino;
        e.attr_timeout = 1.0;
        e.entry_timeout = 1.0;
        e.generation = e.attr.st_ino;

        debug_printf("inserting %s at %d\n", name, fileno);
        FS::name_to_inode.insert({string(name), ino});
        fuse_reply_entry(req, &e);
    } else {
        fuse_reply_err(req, EPERM);
    }
}

static void fiffs_setattr(fuse_req_t req, fuse_ino_t ino, struct stat *attr, int to_set, struct fuse_file_info *fi) {
    if (ino == 1) {
        fuse_reply_err(req, EPERM);
    }
    struct stat new_attr = FS::inodes[ino].st;

    if (FUSE_SET_ATTR_SIZE & to_set) {
        new_attr.st_size = attr->st_size;
        FS::inodes[ino].data.resize(attr->st_size);
    }
    if (FUSE_SET_ATTR_UID & to_set)
        new_attr.st_uid = attr->st_uid;
    if (FUSE_SET_ATTR_GID & to_set)
        new_attr.st_gid = attr->st_gid;
    if (FUSE_SET_ATTR_MODE & to_set)
        new_attr.st_mode = attr->st_mode;
    if (FUSE_SET_ATTR_MTIME & to_set)
        new_attr.st_mtim = attr->st_mtim;
    if (FUSE_SET_ATTR_ATIME & to_set)
        new_attr.st_atim = attr->st_atim;
    if (FUSE_SET_ATTR_ATIME_NOW & to_set)
        clock_gettime(CLOCK_REALTIME, &new_attr.st_atim);
    if (FUSE_SET_ATTR_MTIME & to_set)
        clock_gettime(CLOCK_REALTIME, &new_attr.st_ctim);
    if (FUSE_SET_ATTR_MTIME_NOW & to_set)
        clock_gettime(CLOCK_REALTIME, &new_attr.st_mtim);
    fuse_reply_attr(req, &new_attr, 1.0);
}

static void fiffs_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off,
                        struct fuse_file_info *fi) {
    debug_printf("fiffs_write\n");
    if (ino >= 2) {
        auto &file = FS::inodes[ino];
        file.data.reserve(off + size);
        file.data.resize(std::max(file.data.size(), size + off));
        file.st.st_size = file.data.size();
        memcpy((char *)file.data.data() + off, buf, size);
        fuse_reply_write(req, size);
        return;
    }
    fuse_reply_err(req, EPERM);
}

static void fiffs_init(void *userdata, struct fuse_conn_info *conn) {
    printf("capabilities: %d\n", conn->capable);
    if (conn->capable & FUSE_CAP_SPLICE_WRITE)
        printf("cap splice write enabled\n");
    if (conn->capable & FUSE_CAP_SPLICE_MOVE)
        printf("cap splice move enabled\n");
    conn->want = conn->want | FUSE_CAP_SPLICE_WRITE | FUSE_CAP_SPLICE_MOVE;
}

static void fiffs_flush(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    const int res = 0; // close(dup(fi->fh));
    fuse_reply_err(req, res == -1 ? errno : 0);
}

static const struct fuse_lowlevel_ops fiffs_oper = {
    .init = fiffs_init,
    .lookup = fiffs_lookup,
    .getattr = fiffs_getattr,
    .setattr = fiffs_setattr,
    .mknod = fiffs_mknod,
    .open = fiffs_open,
    .read = fiffs_read,
    .write = fiffs_write,
    .flush = fiffs_flush,
    .readdir = fiffs_readdir,
};

int main(int argc, char *argv[]) {
    struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
    struct fuse_session *se;
    struct fuse_cmdline_opts opts;
    struct fuse_loop_config config;
    int ret = -1;
    uid = getuid();

    if (fuse_parse_cmdline(&args, &opts) != 0)
        return 1;
    if (opts.show_help) {
        printf("usage: %s [options] <mountpoint>\n\n", argv[0]);
        fuse_cmdline_help();
        fuse_lowlevel_help();
        ret = 0;
        goto err_out1;
    } else if (opts.show_version) {
        printf("FUSE library version %s\n", fuse_pkgversion());
        fuse_lowlevel_version();
        ret = 0;
        goto err_out1;
    }

    if (opts.mountpoint == NULL) {
        printf("usage: %s [options] <mountpoint>\n", argv[0]);
        printf("       %s --help\n", argv[0]);
        ret = 1;
        goto err_out1;
    }

    fiffs_debug = opts.debug;

    se = fuse_session_new(&args, &fiffs_oper, sizeof(fiffs_oper), NULL);
    if (se == NULL)
        goto err_out1;

    if (fuse_set_signal_handlers(se) != 0)
        goto err_out2;

    if (fuse_session_mount(se, opts.mountpoint) != 0)
        goto err_out3;

    fuse_daemonize(opts.foreground);

    /* Block until ctrl+c or fusermount -u */
    if (opts.singlethread)
        ret = fuse_session_loop(se);
    else {
        config.clone_fd = opts.clone_fd;
        config.max_idle_threads = opts.max_idle_threads;
        ret = fuse_session_loop_mt(se, &config);
    }

    fuse_session_unmount(se);
err_out3:
    fuse_remove_signal_handlers(se);
err_out2:
    fuse_session_destroy(se);
err_out1:
    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    return ret ? 1 : 0;
}
} // namespace fiffs

int main(int argc, char *argv[]) { return fiffs::main(argc, argv); }
