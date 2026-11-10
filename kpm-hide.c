/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * kpm-hide - kernel-level hiding for a daily-driver rooted device
 *
 * Features (only affect regular apps, uid >= 10000):
 *  1. File hiding      : openat/faccessat/faccessat2/fstatat/statx/readlinkat
 *                        return -ENOENT for hidden paths (root artifacts etc.)
 *  2. Directory hiding : getdents64 entries filtered
 *  3. Debugger traces  : /proc/[pid]/status TracerPid -> 0,
 *                        "t (tracing stop)" -> "S (sleeping)", wchan, stat
 *  4. Mountinfo hiding : root-related mount lines dropped from /proc/[pid]/mountinfo
 *  5. Maps hiding      : injected libs (zygisk/lsposed/frida) hidden in /proc/[pid]/maps
 *  6. Dynamic config   : CTL0 interface (add/del/list/clear/status)
 *
 * Credits: bmax121/KernelPatch, Beransnow, cxapython/mkpms (anti-detect),
 *          P4nda0s/kpm-panda-hide, lzghzr/kpm
 */

#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <linux/printk.h>
#include <uapi/asm-generic/unistd.h>
#include <uapi/asm-generic/errno.h>
#include <linux/string.h>
#include <syscall.h>
#include <kputils.h>
#include <linux/kallsyms.h>
#include <hook.h>
#include <asm/current.h>

KPM_NAME("kpm-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("liujinbin1212");
KPM_DESCRIPTION("Kernel-level file/process/mountinfo/maps hiding for apps");

#define AID_APP_START 10000
#define NAME_BUF 256
#define GFP_KERNEL_VAL 0xcc0
#define MAX_DYN 32
#define MAX_STR 128

#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif

/* ------------------------------------------------------------------ */
/* kernel symbols resolved at load time                                */
/* ------------------------------------------------------------------ */

static void *(*kfn_kmalloc)(size_t size, unsigned int flags);
static void (*kfn_kfree)(const void *ptr);
static unsigned long (*kfn_copy_from_user)(void *to, const void __user *from, unsigned long n);

static int resolve_symbols(void)
{
    kfn_kmalloc = (void *(*)(size_t, unsigned int))kallsyms_lookup_name("kmalloc");
    if (!kfn_kmalloc)
        kfn_kmalloc = (void *(*)(size_t, unsigned int))kallsyms_lookup_name("__kmalloc");
    kfn_kfree = (void (*)(const void *))kallsyms_lookup_name("kfree");
    kfn_copy_from_user = (unsigned long (*)(void *, const void __user *, unsigned long))kallsyms_lookup_name("_copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (unsigned long (*)(void *, const void __user *, unsigned long))kallsyms_lookup_name("copy_from_user");
    if (!kfn_copy_from_user)
        kfn_copy_from_user = (unsigned long (*)(void *, const void __user *, unsigned long))kallsyms_lookup_name("__arch_copy_from_user");
    if (!kfn_kmalloc || !kfn_kfree || !kfn_copy_from_user) {
        pr_err("kpm-hide: required symbols missing (kmalloc=%px kfree=%px cfu=%px)\n",
               kfn_kmalloc, kfn_kfree, kfn_copy_from_user);
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* hidden lists                                                        */
/* ------------------------------------------------------------------ */

/* substring match against the full path */
static const char *hide_path_sub[] = {
    "magisk", "Magisk",
    "supersu", "Superuser", "SuperSU", "daemonsu",
    "kpatch", "kpimg",
    "ksud", "/ksu", "/data/adb",
    "shamiko", "zygisk", "lsposed", "riru",
    0,
};

/* directory-entry names: exact match */
static const char *hide_name_exact[] = { "su", "ksu", "ksud", "kpatch", "apd", "busybox", 0 };
/* directory-entry names: substring match */
static const char *hide_name_sub[] = { "magisk", "supersu", "Superuser", "daemonsu", "zygisk", "shamiko", 0 };

/* dynamic entries added via CTL0 */
static char *dyn_paths[MAX_DYN];
static int dyn_count;

static int path_hidden(const char *path)
{
    const char **p;
    int i;
    for (p = hide_path_sub; *p; p++)
        if (strstr(path, *p))
            return 1;
    for (i = 0; i < dyn_count; i++)
        if (dyn_paths[i] && strstr(path, dyn_paths[i]))
            return 1;
    return 0;
}

static int name_hidden(const char *name)
{
    const char **p;
    int i;
    for (p = hide_name_exact; *p; p++)
        if (strcmp(name, *p) == 0)
            return 1;
    for (p = hide_name_sub; *p; p++)
        if (strstr(name, *p))
            return 1;
    for (i = 0; i < dyn_count; i++)
        if (dyn_paths[i] && strstr(name, dyn_paths[i]))
            return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 1+2: file & directory syscall hooks                                 */
/* ------------------------------------------------------------------ */

struct ldirent64 {
    uint64_t d_ino;
    int64_t d_off;
    unsigned short d_reclen;
    unsigned char d_type;
    char d_name[];
};
#define LD_RECLENN_OFF 16
#define LD_NAME_OFF 19

static void before_path(hook_fargs4_t *args, void *udata)
{
    const char __user *upath;
    char buf[NAME_BUF];
    long len;

    if (current_uid() < AID_APP_START) return;
    upath = (const char __user *)syscall_argn(args, 1);
    if (!upath) return;

    len = compat_strncpy_from_user(buf, upath, sizeof(buf));
    if (len <= 0) return;

    if (path_hidden(buf)) {
        args->ret = -ENOENT;
        args->skip_origin = 1;
    }
}

static int getdents_has_hidden(char __user *ubuf, long len)
{
    char __user *pos = ubuf;
    char __user *end = ubuf + len;
    unsigned short reclen;
    char name[NAME_BUF];

    while (pos < end) {
        if (kfn_copy_from_user(&reclen, pos + LD_RECLENN_OFF, sizeof(reclen)))
            return 0;
        if (reclen == 0 || pos + reclen > end)
            break;
        if (compat_strncpy_from_user(name, pos + LD_NAME_OFF, sizeof(name)) > 0 && name_hidden(name))
            return 1;
        pos += reclen;
    }
    return 0;
}

static void after_getdents64(hook_fargs4_t *args, void *udata)
{
    long ret = (long)args->ret;
    char __user *ubuf;
    char *kbuf, *src, *end, *dst;
    long new_ret = 0;

    if (current_uid() < AID_APP_START) return;
    if (ret <= 0) return;
    ubuf = (char __user *)syscall_argn(args, 1);

    if (!getdents_has_hidden(ubuf, ret))
        return;
    if (ret > 256 * 1024)
        return;

    kbuf = kfn_kmalloc((size_t)ret, GFP_KERNEL_VAL);
    if (!kbuf) return;
    if (kfn_copy_from_user(kbuf, ubuf, (unsigned long)ret)) {
        kfn_kfree(kbuf);
        return;
    }

    src = kbuf;
    end = kbuf + ret;
    dst = kbuf;
    while (src < end) {
        struct ldirent64 *d = (struct ldirent64 *)src;
        unsigned short reclen = d->d_reclen;
        if (reclen == 0 || src + reclen > end)
            break;
        if (!name_hidden(d->d_name)) {
            if (dst != src)
                memmove(dst, src, reclen);
            dst += reclen;
            new_ret += reclen;
        }
        src += reclen;
    }

    if (new_ret != ret) {
        if (new_ret == 0 || compat_copy_to_user(ubuf, kbuf, (int)new_ret) == new_ret)
            args->ret = new_ret;
    }
    kfn_kfree(kbuf);
}

struct syscall_hook {
    int nr;
    int narg;
    void *before;
    void *after;
};

static const struct syscall_hook sc_hooks[] = {
    { __NR_openat,         3, before_path, 0 },
    { __NR_faccessat,      3, before_path, 0 },
    { __NR_faccessat2,     4, before_path, 0 },
    { __NR3264_fstatat,    4, before_path, 0 },
    { __NR_statx,          5, before_path, 0 },
    { __NR_readlinkat,     4, before_path, 0 },
    { __NR_getdents64,     3, 0, after_getdents64 },
};
#define NUM_SC_HOOKS (sizeof(sc_hooks) / sizeof(sc_hooks[0]))
static int sc_installed;

/* ------------------------------------------------------------------ */
/* 3: debugger traces                                                  */
/* ------------------------------------------------------------------ */

typedef struct kseq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
} kseq_file_t;

static void before_seq_put_decimal_ull(hook_fargs3_t *args, void *udata)
{
    const char *s;
    if (current_uid() < AID_APP_START) return;
    s = (const char *)args->arg1;
    if (s && strcmp(s, "\nTracerPid:\t") == 0 && args->arg2 != 0)
        args->arg2 = 0;
}

static void before_seq_puts(hook_fargs2_t *args, void *udata)
{
    const char *s;
    if (current_uid() < AID_APP_START) return;
    s = (const char *)args->arg1;
    if (s && strcmp(s, "t (tracing stop)") == 0)
        args->arg1 = (uint64_t)"S (sleeping)";
}

static void after_proc_pid_wchan(hook_fargs4_t *args, void *udata)
{
    kseq_file_t *m;
    if (current_uid() < AID_APP_START) return;
    m = (kseq_file_t *)args->arg0;
    if (m && m->buf && strcmp(m->buf, "ptrace_stop") == 0) {
        m->buf[0] = '0';
        m->buf[1] = '\0';
        m->count = 1;
    }
}

static void after_do_task_stat(hook_fargs5_t *args, void *udata)
{
    kseq_file_t *m;
    size_t i;
    if (current_uid() < AID_APP_START) return;
    m = (kseq_file_t *)args->arg0;
    if (m && m->buf) {
        for (i = 0; i + 2 < m->count; i++) {
            if (m->buf[i] == ')' && m->buf[i + 1] == ' ') {
                if (m->buf[i + 2] == 't')
                    m->buf[i + 2] = 'S';
                break;
            }
        }
    }
}

/* ------------------------------------------------------------------ */
/* bounded substring helpers (seq buffers are not NUL-terminated)      */
/* ------------------------------------------------------------------ */

static int bounded_contains(const char *buf, size_t from, size_t to, const char *needle)
{
    size_t nlen = strlen(needle);
    size_t i;
    if (nlen == 0 || to < from || to - from < nlen)
        return 0;
    for (i = from; i + nlen <= to; i++) {
        if (buf[i] == needle[0] && memcmp(buf + i, needle, nlen) == 0)
            return 1;
    }
    return 0;
}

static const char *mount_markers[] = { "magisk", "/data/adb", "kpatch", "ksu", "ksud", "zygisk", "supersu", 0 };
static const char *map_markers[] = { "frida", "gadget", "/data/adb", "zygisk", "lsposed", "riru", 0 };

static int range_has_marker(const char *buf, size_t from, size_t to, const char **markers)
{
    const char **m;
    for (m = markers; *m; m++)
        if (bounded_contains(buf, from, to, *m))
            return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* 4: /proc/[pid]/mountinfo line filtering                                 */
/* ------------------------------------------------------------------ */

static void before_show_mountinfo(hook_fargs2_t *args, void *udata)
{
    kseq_file_t *m = (kseq_file_t *)args->arg0;
    if (m)
        args->local.data0 = m->count;
}

static void after_show_mountinfo(hook_fargs2_t *args, void *udata)
{
    kseq_file_t *m;
    size_t start, i, w;
    if (current_uid() < AID_APP_START) return;
    m = (kseq_file_t *)args->arg0;
    if (!m || !m->buf) return;
    start = (size_t)args->local.data0;
    if (start > m->count) start = 0;

    i = start;
    w = start;
    while (i < m->count) {
        size_t e = i;
        while (e < m->count && m->buf[e] != '\n')
            e++;
        if (e < m->count)
            e++; /* include '\n' */
        if (range_has_marker(m->buf, i, e, mount_markers)) {
            /* drop this line */
        } else {
            if (w != i)
                memmove(m->buf + w, m->buf + i, e - i);
            w += e - i;
        }
        i = e;
    }
    m->count = w;
}

/* ------------------------------------------------------------------ */
/* 5: /proc/[pid]/maps entry filtering                                     */
/* ------------------------------------------------------------------ */

static void before_show_map_vma(hook_fargs2_t *args, void *udata)
{
    kseq_file_t *m = (kseq_file_t *)args->arg0;
    if (m)
        args->local.data0 = m->count;
}

static void after_show_map_vma(hook_fargs2_t *args, void *udata)
{
    kseq_file_t *m;
    size_t start;
    if (current_uid() < AID_APP_START) return;
    m = (kseq_file_t *)args->arg0;
    if (!m || !m->buf) return;
    start = (size_t)args->local.data0;
    if (start > m->count) start = 0;
    if (range_has_marker(m->buf, start, m->count, map_markers))
        m->count = start;
}

/* ------------------------------------------------------------------ */
/* function hooks (best effort: missing symbols are skipped)           */
/* ------------------------------------------------------------------ */

struct fhook {
    const char *name;
    int narg;
    void *before;
    void *after;
    void *addr;
    int installed;
};

static struct fhook wrap_hooks[] = {
    { "seq_put_decimal_ull", 3, before_seq_put_decimal_ull, 0, 0, 0 },
    { "seq_puts",            2, before_seq_puts, 0, 0, 0 },
    { "proc_pid_wchan",      4, 0, after_proc_pid_wchan, 0, 0 },
    { "do_task_stat",        5, 0, after_do_task_stat, 0, 0 },
    { "show_mountinfo",      2, before_show_mountinfo, after_show_mountinfo, 0, 0 },
    { "show_map_vma",        2, before_show_map_vma, after_show_map_vma, 0, 0 },
};
#define NUM_WRAP_HOOKS (sizeof(wrap_hooks) / sizeof(wrap_hooks[0]))

static int wrap_install_all(void)
{
    int i, ok = 0;
    for (i = 0; i < (int)NUM_WRAP_HOOKS; i++) {
        struct fhook *h = &wrap_hooks[i];
        hook_err_t err;
        h->addr = (void *)kallsyms_lookup_name(h->name);
        if (!h->addr) {
            pr_warn("kpm-hide: symbol not found: %s (skipped)\n", h->name);
            continue;
        }
        err = hook_wrap(h->addr, h->narg, h->before, h->after, 0);
        if (err) {
            pr_warn("kpm-hide: hook %s failed: %d\n", h->name, err);
            h->addr = 0;
            continue;
        }
        h->installed = 1;
        ok++;
    }
    return ok;
}

static void wrap_uninstall_all(void)
{
    int i;
    for (i = 0; i < (int)NUM_WRAP_HOOKS; i++) {
        struct fhook *h = &wrap_hooks[i];
        if (h->installed && h->addr) {
            hook_unwrap(h->addr, h->before, h->after);
            h->installed = 0;
        }
        h->addr = 0;
    }
}

/* ------------------------------------------------------------------ */
/* 6: CTL0 dynamic configuration                                       */
/* ------------------------------------------------------------------ */

static char *append_str(char *p, const char *s)
{
    while (*s)
        *p++ = *s++;
    return p;
}

static char *append_dec(char *p, int v)
{
    char tmp[12];
    int n = 0;
    if (v == 0) {
        *p++ = '0';
        return p;
    }
    if (v < 0) {
        *p++ = '-';
        v = -v;
    }
    while (v) {
        tmp[n++] = (char)('0' + v % 10);
        v /= 10;
    }
    while (n)
        *p++ = tmp[--n];
    return p;
}

static long write_msg(char *__user out_msg, int outlen, const char *msg)
{
    int len = strlen(msg);
    if (outlen > 0 && len > outlen)
        len = outlen;
    if (out_msg && len > 0)
        compat_copy_to_user(out_msg, msg, len);
    return 0;
}

static long hide_ctl0(const char *args, char *__user out_msg, int outlen)
{
    if (!args)
        return write_msg(out_msg, outlen, "usage: add <str> | del <str> | list | clear | status");

    if (strncmp(args, "add ", 4) == 0) {
        const char *s = args + 4;
        size_t slen = strlen(s);
        if (slen == 0 || slen >= MAX_STR)
            return write_msg(out_msg, outlen, "err: bad length");
        if (dyn_count >= MAX_DYN)
            return write_msg(out_msg, outlen, "err: list full");
        dyn_paths[dyn_count] = kfn_kmalloc(MAX_STR, GFP_KERNEL_VAL);
        if (!dyn_paths[dyn_count])
            return write_msg(out_msg, outlen, "err: no mem");
        strncpy(dyn_paths[dyn_count], s, MAX_STR - 1);
        dyn_paths[dyn_count][MAX_STR - 1] = '\0';
        dyn_count++;
        return write_msg(out_msg, outlen, "ok: added");
    }

    if (strncmp(args, "del ", 4) == 0) {
        const char *s = args + 4;
        int i, j;
        for (i = 0; i < dyn_count; i++) {
            if (dyn_paths[i] && strcmp(dyn_paths[i], s) == 0) {
                kfn_kfree(dyn_paths[i]);
                for (j = i; j < dyn_count - 1; j++)
                    dyn_paths[j] = dyn_paths[j + 1];
                dyn_count--;
                dyn_paths[dyn_count] = 0;
                return write_msg(out_msg, outlen, "ok: deleted");
            }
        }
        return write_msg(out_msg, outlen, "err: not found");
    }

    if (strcmp(args, "clear") == 0) {
        int i;
        for (i = 0; i < dyn_count; i++) {
            if (dyn_paths[i])
                kfn_kfree(dyn_paths[i]);
            dyn_paths[i] = 0;
        }
        dyn_count = 0;
        return write_msg(out_msg, outlen, "ok: cleared");
    }

    if (strcmp(args, "list") == 0) {
        char buf[1024];
        int i, off = 0;
        buf[0] = '\0';
        for (i = 0; i < dyn_count && off < (int)sizeof(buf) - MAX_STR; i++) {
            int n = strlen(dyn_paths[i]);
            memcpy(buf + off, dyn_paths[i], n);
            off += n;
            buf[off++] = '\n';
        }
        buf[off] = '\0';
        return write_msg(out_msg, outlen, buf);
    }

    if (strcmp(args, "status") == 0) {
        char buf[256];
        char *p = buf;
        int i, wok = 0;
        for (i = 0; i < (int)NUM_WRAP_HOOKS; i++)
            if (wrap_hooks[i].installed)
                wok++;
        p = append_str(p, "syscall hooks: ");
        p = append_dec(p, sc_installed);
        p = append_str(p, "/");
        p = append_dec(p, (int)NUM_SC_HOOKS);
        p = append_str(p, ", func hooks: ");
        p = append_dec(p, wok);
        p = append_str(p, "/");
        p = append_dec(p, (int)NUM_WRAP_HOOKS);
        p = append_str(p, ", dyn entries: ");
        p = append_dec(p, dyn_count);
        p = append_str(p, "/");
        p = append_dec(p, MAX_DYN);
        *p = '\0';
        return write_msg(out_msg, outlen, buf);
    }

    return write_msg(out_msg, outlen, "usage: add <str> | del <str> | list | clear | status");
}

/* ------------------------------------------------------------------ */
/* module lifecycle                                                    */
/* ------------------------------------------------------------------ */

static long hide_init(const char *args, const char *event, void *__user reserved)
{
    int i;
    pr_info("kpm-hide: loading (event: %s, args: %s), kpver: %x\n", event, args ? args : "", kpver);

    if (resolve_symbols())
        return -1;

    for (sc_installed = 0; sc_installed < (int)NUM_SC_HOOKS; sc_installed++) {
        const struct syscall_hook *h = &sc_hooks[sc_installed];
        hook_err_t err = hook_syscalln(h->nr, h->narg, h->before, h->after, 0);
        if (err) {
            pr_err("kpm-hide: hook syscall %d failed: %d\n", h->nr, err);
            while (sc_installed-- > 0) {
                const struct syscall_hook *hh = &sc_hooks[sc_installed];
                unhook_syscalln(hh->nr, hh->before, hh->after);
            }
            sc_installed = 0;
            return -1;
        }
    }
    pr_info("kpm-hide: %d syscall hooks installed\n", sc_installed);

    i = wrap_install_all();
    pr_info("kpm-hide: %d/%d function hooks installed\n", i, (int)NUM_WRAP_HOOKS);

    pr_info("kpm-hide: loaded\n");
    return 0;
}

static long hide_exit(void *__user reserved)
{
    int i;
    wrap_uninstall_all();
    for (i = 0; i < sc_installed; i++) {
        const struct syscall_hook *h = &sc_hooks[i];
        unhook_syscalln(h->nr, h->before, h->after);
    }
    sc_installed = 0;
    pr_info("kpm-hide: unloaded\n");
    return 0;
}

KPM_INIT(hide_init);
KPM_CTL0(hide_ctl0);
KPM_EXIT(hide_exit);
