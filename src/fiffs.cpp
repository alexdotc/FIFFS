/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * minimal example filesystem using low-level API
 *
 * Compile with:
 *
 *     gcc -Wall hello_ll.c `pkg-config fuse3 --cflags --libs` -o hello_ll
 *
 * ## Source code ##
 * \include hello_ll.c
 */

#include <sys/stat.h>
#define FUSE_USE_VERSION 33

#include <fuse3/fuse_lowlevel.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <vector>
#include <string>

using std::string;
using std::vector;

static int uid = 0;

struct Inode {
    string name;
    string data;

    size_t namelength() { return name.length(); }
    size_t size() { return data.size(); }
    const char *cbuf() { return data.data(); }
};

static vector<Inode> files = {{"foo", "foodat\n"}, {"bar", "bardat\n"}};

static int fiffs_stat(fuse_ino_t ino, struct stat *stbuf) {
    stbuf->st_ino = ino;
    int fileno = ino - 2;
    printf("fiffs_stat %d\n", fileno);
    if (ino == 1) {
        stbuf->st_uid = stbuf->st_gid = uid;
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    } else if (fileno > files.size())
        return -1;

    stbuf->st_uid = stbuf->st_gid = uid;
    stbuf->st_mode = S_IFREG | 0666;
    stbuf->st_nlink = 1;
    stbuf->st_size = files[fileno].size();

    return 0;
}

static void fiffs_getattr(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    struct stat stbuf;
    printf("fiffs_getattr\n");
    (void)fi;

    memset(&stbuf, 0, sizeof(stbuf));
    if (fiffs_stat(ino, &stbuf) == -1)
        fuse_reply_err(req, ENOENT);
    else
        fuse_reply_attr(req, &stbuf, 1.0);
}

static void fiffs_lookup(fuse_req_t req, fuse_ino_t parent, const char *name) {
    printf("fiffs_lookup %s\n", name);
    struct fuse_entry_param e;

    if (parent != 1)
        fuse_reply_err(req, ENOENT);
    else {
        memset(&e, 0, sizeof(e));

        for (int i = 0; i < files.size(); i++) {
            if (files[i].name == string(name)) {
                e.ino = i + 2;
                e.attr_timeout = 1.0;
                e.entry_timeout = 1.0;
                fiffs_stat(e.ino, &e.attr);
                printf("%ld\n", e.ino);

                fuse_reply_entry(req, &e);
            }
        }
        fuse_reply_err(req, ENOENT);
    }
}

struct dirbuf {
    char *p;
    size_t size;
};

static void dirbuf_add(fuse_req_t req, struct dirbuf *b, const char *name, fuse_ino_t ino) {
    struct stat stbuf;
    size_t oldsize = b->size;
    b->size += fuse_add_direntry(req, NULL, 0, name, NULL, 0);
    b->p = (char *)realloc(b->p, b->size);
    memset(&stbuf, 0, sizeof(stbuf));
    stbuf.st_ino = ino;
    fuse_add_direntry(req, b->p + oldsize, b->size - oldsize, name, &stbuf, b->size);
}

static int reply_buf_limited(fuse_req_t req, const char *buf, size_t bufsize, off_t off, size_t maxsize) {
    if (off < bufsize)
        return fuse_reply_buf(req, buf + off, std::min(bufsize - off, maxsize));
    else
        return fuse_reply_buf(req, NULL, 0);
}

static void fiffs_readdir(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    printf("fiffs_readdir\n");
    (void)fi;

    if (ino != 1)
        fuse_reply_err(req, ENOTDIR);
    else {
        struct dirbuf b;

        memset(&b, 0, sizeof(b));
        dirbuf_add(req, &b, ".", 1);
        dirbuf_add(req, &b, "..", 1);
        for (int i = 0; i < files.size(); ++i)
            dirbuf_add(req, &b, files[i].name.c_str(), 2 + i);
        reply_buf_limited(req, b.p, b.size, off, size);
        free(b.p);
    }
}

static void fiffs_open(fuse_req_t req, fuse_ino_t ino, struct fuse_file_info *fi) {
    printf("fiffs_open\n");
    if (ino < 2)
        fuse_reply_err(req, EISDIR);
    else
        fuse_reply_open(req, fi);
}

static void fiffs_read(fuse_req_t req, fuse_ino_t ino, size_t size, off_t off, struct fuse_file_info *fi) {
    printf("fiffs_read\n");
    (void)fi;

    reply_buf_limited(req, files[ino - 2].cbuf(), files[ino - 2].data.size(), off, size);
}

static void fiffs_mknod(fuse_req_t req, fuse_ino_t parent, const char *name, mode_t mode, dev_t rdev) {
    printf("fiffs_mknod\n");
    if (parent == 1 && S_ISREG(mode)) {
        files.push_back({name, ""});

        fuse_entry_param e;
        memset(&e, 0, sizeof(e));
        fiffs_stat(files.size() - 2, &e.attr);
        e.attr.st_mode = mode;
        e.attr_timeout = 1.0;
        e.entry_timeout = 1.0;
        e.generation = e.attr.st_ino;

        fuse_reply_entry(req, &e);
    } else {
        fuse_reply_err(req, EPERM);
    }
}

static void fiffs_write(fuse_req_t req, fuse_ino_t ino, const char *buf, size_t size, off_t off,
                        struct fuse_file_info *fi) {
    printf("fiffs_write\n");
    if (ino >= 2) {
        auto &file = files[ino - 2];
        file.data.reserve(off + size);
        file.data.resize(std::max(file.data.size(), size + off));
        memcpy((char *)file.data.data() + off, buf, size);
        fuse_reply_write(req, size);
        return;
    }
    fuse_reply_err(req, EPERM);
}

static const struct fuse_lowlevel_ops fiffs_oper = {
    .lookup = fiffs_lookup,
    .getattr = fiffs_getattr,
    .mknod = fiffs_mknod,
    .open = fiffs_open,
    .read = fiffs_read,
    .write = fiffs_write,
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
