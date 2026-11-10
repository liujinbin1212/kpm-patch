/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * hosts_file_redirect - redirect /system/etc/hosts to /data/adb/hosts
 * Adapted for SukiSU KernelPatch (ShirkNeko fork) from lzghzr/kpm (by skkk).
 * - netd (uid 0) opening /system/etc/hosts is redirected to /data/adb/hosts
 * - SELinux allow is granted via KP task_ext during the open, restored after
 * - if redirect fails, falls back to the original hosts file
 * Usage: create /data/adb/hosts with your entries (same format).
 */

#include <linux/err.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/string.h>

#include <kpmodule.h>
#include <kputils.h>
#include <accctl.h>
#include <asm/current.h>
#include <common.h>
#include <hook.h>

#include "kpm_hook_utils.h"

KPM_NAME("hosts_file_redirect");
KPM_VERSION("1.0.0-suksu");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("skkk, liujinbin1212");
KPM_DESCRIPTION("hosts file redirect: /system/etc/hosts -> /data/adb/hosts");

static const char hostsOrigPath[] = "/system/etc/hosts";
static const char hostsRedirectPath[] = "/data/adb/hosts";

struct open_flags;
hook_func_def(do_filp_open, struct file *, int dfd, struct filename *pathname, const struct open_flags *o);
hook_func_no_info(do_filp_open);

static struct file *hook_replace(do_filp_open)(int dfd, struct filename *pathname, const struct open_flags *o)
{
    if (unlikely(!strcmp(hostsOrigPath, pathname->name))) {
        bool replace = false;
        const char *originName = NULL;
        /* netd runs as root */
        if (current_uid() == 0) {
            replace = true;
            originName = pathname->name;
            pathname->name = hostsRedirectPath;
            set_priv_sel_allow(current, 1);
        }

        struct file *f = hook_call_backup(do_filp_open, dfd, pathname, o);

        if (replace) {
            set_priv_sel_allow(current, 0);
            pathname->name = originName;
            /* retry with the original path on failure */
            if (IS_ERR(f))
                f = hook_call_backup(do_filp_open, dfd, pathname, o);
        }
        return f;
    }
    return hook_call_backup(do_filp_open, dfd, pathname, o);
}

static inline bool installHook(void)
{
    if (!hook_success(do_filp_open)) {
        hook_install(do_filp_open);
        if (!hook_success(do_filp_open))
            goto exit;
        pr_info("HFR: hosts file is: '%s'\n", hostsRedirectPath);
        pr_info("HFR: enabled!\n");
    } else {
        pr_info("HFR: already enabled!\n");
    }
    return true;

exit:
    return false;
}

static inline bool uninstallHook(void)
{
    if (hook_success(do_filp_open)) {
        unhook((void *)hook_original(do_filp_open));
        hook_err(do_filp_open) = HOOK_NOT_HOOK;
        pr_info("HFR: disabled!\n");
    }
    return true;
}

static inline void writeOutMsg(char *__user out_msg, int *outlen, const char *msg)
{
    *outlen = strlen(msg);
    compat_copy_to_user(out_msg, msg, *outlen);
}

static long hosts_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("HFR: initializing (event: %s), kpver: %x\n", event ? event : "", kpver);
    return installHook() ? 0 : 1;
}

static long hosts_ctl0(const char *args, char *__user out_msg, int outlen)
{
    if (args) {
        if (strncmp(args, "enable", 6) == 0) {
            writeOutMsg(out_msg, &outlen, installHook() ? "HFR: enabled!" : "HFR: enable failed!");
        } else if (strncmp(args, "disable", 7) == 0) {
            writeOutMsg(out_msg, &outlen, uninstallHook() ? "HFR: disabled!" : "HFR: disable failed!");
        } else {
            writeOutMsg(out_msg, &outlen, "HFR: usage: enable | disable");
            return -1;
        }
    }
    return 0;
}

static long hosts_exit(void *__user reserved)
{
    uninstallHook();
    pr_info("HFR: exited\n");
    return 0;
}

KPM_INIT(hosts_init);
KPM_CTL0(hosts_ctl0);
KPM_EXIT(hosts_exit);
