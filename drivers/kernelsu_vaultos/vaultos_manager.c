// SPDX-License-Identifier: GPL-2.0
/*
 * VaultOs KernelSU-Next preinstalled manager crowning helper.
 *
 * Upstream KernelSU-Next's throne_tracker scans only /data/app for the
 * manager APK. On VaultOs, KernelSU-Next is preinstalled cleanly as a
 * non-updatable system app at /product/app/KernelSU/KernelSU.apk, so the
 * APK signature is verified directly against that immutable path once
 * com.rifsxd.ksunext appears in /data/system/packages.list.
 */

#define pr_fmt(fmt) "vaultos_ksu: " fmt

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/jiffies.h>
#include <linux/kernel.h>
#include <linux/lsm_hooks.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "include/ksu.h"
#include "manager/apk_sign.h"
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wstrict-prototypes"
#endif
#include "manager/manager_identity.h"
#ifdef __clang__
#pragma clang diagnostic pop
#endif

#define VAULTOS_KSU_MANAGER_PKG "com.rifsxd.ksunext"
#define VAULTOS_PACKAGES_LIST "/data/system/packages.list"
#define VAULTOS_APK_PATH_PRODUCT "/product/app/KernelSU/KernelSU.apk"
#define VAULTOS_APK_PATH_SYSPROD "/system/product/app/KernelSU/KernelSU.apk"
#define VAULTOS_MAX_BOOT_RETRIES 60
#define VAULTOS_RETRY_MS 2000

static DEFINE_MUTEX(vaultos_mgr_mutex);
static struct delayed_work vaultos_mgr_work;
static int vaultos_boot_retries;
static atomic_t vaultos_rename_seen = ATOMIC_INIT(0);

static bool vaultos_parse_pkg_line(char *line, uid_t *appid_out)
{
	char *space1;
	char *uid_str;
	char *end;
	u32 uid;

	space1 = strchr(line, ' ');
	if (!space1)
		return false;

	*space1 = '\0';
	if (strcmp(line, VAULTOS_KSU_MANAGER_PKG) != 0)
		return false;

	uid_str = space1 + 1;
	while (*uid_str == ' ' || *uid_str == '\t')
		uid_str++;
	end = strpbrk(uid_str, " \t");
	if (end)
		*end = '\0';

	if (kstrtou32(uid_str, 10, &uid) != 0)
		return false;

	*appid_out = (uid_t)(uid % KSU_PER_USER_RANGE);
	return true;
}

static bool vaultos_find_manager_appid(uid_t *appid_out)
{
	struct file *fp;
	char *chunk;
	char line[512];
	size_t lpos = 0;
	loff_t fpos = 0;
	ssize_t nread;
	bool found = false;

	fp = filp_open(VAULTOS_PACKAGES_LIST, O_RDONLY, 0);
	if (IS_ERR(fp))
		return false;

	chunk = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!chunk) {
		filp_close(fp, NULL);
		return false;
	}

	while ((nread = kernel_read(fp, chunk, PAGE_SIZE, &fpos)) > 0) {
		ssize_t i;

		for (i = 0; i < nread; i++) {
			char c = chunk[i];

			if (c == '\n' || c == '\r') {
				if (lpos > 0) {
					line[lpos] = '\0';
					if (vaultos_parse_pkg_line(line, appid_out)) {
						found = true;
						goto out;
					}
					lpos = 0;
				}
			} else if (lpos < sizeof(line) - 1) {
				line[lpos++] = c;
			}
		}
	}

	if (lpos > 0) {
		line[lpos] = '\0';
		found = vaultos_parse_pkg_line(line, appid_out);
	}

out:
	kfree(chunk);
	filp_close(fp, NULL);
	return found;
}

static bool vaultos_verify_preinstalled_apk(void)
{
	char path_buf[64];

	strscpy(path_buf, VAULTOS_APK_PATH_PRODUCT, sizeof(path_buf));
	if (is_manager_apk(path_buf))
		return true;

	strscpy(path_buf, VAULTOS_APK_PATH_SYSPROD, sizeof(path_buf));
	return is_manager_apk(path_buf);
}

static void vaultos_mgr_work_fn(struct work_struct *work)
{
	const struct cred *saved_cred;
	uid_t appid = 0;
	bool renamed;
	bool found_uid;
	bool sig_ok = false;

	if (ksu_is_manager_appid_valid())
		return;

	if (!ksu_cred)
		goto reschedule;

	mutex_lock(&vaultos_mgr_mutex);
	if (ksu_is_manager_appid_valid()) {
		mutex_unlock(&vaultos_mgr_mutex);
		return;
	}

	saved_cred = override_creds(ksu_cred);
	found_uid = vaultos_find_manager_appid(&appid);
	if (found_uid)
		sig_ok = vaultos_verify_preinstalled_apk();
	revert_creds(saved_cred);

	if (found_uid && sig_ok && !ksu_is_manager_appid_valid()) {
		pr_info("Crowning preinstalled manager %s (appid=%u)\n",
			VAULTOS_KSU_MANAGER_PKG, appid);
		ksu_set_manager_appid(appid);
		mutex_unlock(&vaultos_mgr_mutex);
		return;
	}
	mutex_unlock(&vaultos_mgr_mutex);

reschedule:
	renamed = atomic_xchg(&vaultos_rename_seen, 0) != 0;
	if (renamed || vaultos_boot_retries < VAULTOS_MAX_BOOT_RETRIES) {
		if (!renamed)
			vaultos_boot_retries++;
		schedule_delayed_work(&vaultos_mgr_work,
				      msecs_to_jiffies(VAULTOS_RETRY_MS));
	}
}

static int vaultos_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
				struct inode *new_dir, struct dentry *new_dentry)
{
	if (likely(ksu_is_manager_appid_valid()))
		return 0;

	if (new_dentry && new_dentry->d_name.len == 13 &&
	    memcmp(new_dentry->d_name.name, "packages.list", 13) == 0) {
		atomic_set(&vaultos_rename_seen, 1);
		mod_delayed_work(system_wq, &vaultos_mgr_work,
				 msecs_to_jiffies(200));
	}

	return 0;
}

static struct security_hook_list vaultos_ksu_hooks[] = {
	LSM_HOOK_INIT(inode_rename, vaultos_inode_rename),
};

static int __init vaultos_ksu_manager_init(void)
{
	INIT_DELAYED_WORK(&vaultos_mgr_work, vaultos_mgr_work_fn);
	security_add_hooks(vaultos_ksu_hooks, ARRAY_SIZE(vaultos_ksu_hooks),
			   "vaultos_ksu");
	schedule_delayed_work(&vaultos_mgr_work,
			      msecs_to_jiffies(VAULTOS_RETRY_MS));
	pr_info("Preinstalled KernelSU-Next manager helper initialized\n");
	return 0;
}
late_initcall(vaultos_ksu_manager_init);
