/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * KPM base module (pipeline validation)
 * Target: Xiaomi 15 Pro (haotian) kernel 6.6.118-android15-8 GKI, SukiSU Ultra
 * Based on KernelPatch demo by bmax121
 */

#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <common.h>
#include <kputils.h>
#include <linux/string.h>

///< The name of the module, each KPM must has a unique name.
KPM_NAME("kpm-base");

///< The version of the module.
KPM_VERSION("1.0.0");

///< The license type.
KPM_LICENSE("GPL v2");

///< The author.
KPM_AUTHOR("liujinbin1212");

///< The description.
KPM_DESCRIPTION("KPM base module for Xiaomi 15 Pro (6.6.118 android15-8 GKI)");

static long base_init(const char *args, const char *event, void *__user reserved)
{
    pr_info("kpm-base init, event: %s, args: %s\n", event, args);
    pr_info("kernelpatch version: %x\n", kpver);
    return 0;
}

static long base_control0(const char *args, char *__user out_msg, int outlen)
{
    pr_info("kpm-base control0, args: %s\n", args);
    char echo[64] = "echo: ";
    strncat(echo, args, 48);
    compat_copy_to_user(out_msg, echo, sizeof(echo));
    return 0;
}

static long base_control1(void *a1, void *a2, void *a3)
{
    pr_info("kpm-base control1, a1: %llx, a2: %llx, a3: %llx\n", a1, a2, a3);
    return 0;
}

static long base_exit(void *__user reserved)
{
    pr_info("kpm-base exit\n");
    return 0;
}

KPM_INIT(base_init);
KPM_CTL0(base_control0);
KPM_CTL1(base_control1);
KPM_EXIT(base_exit);
