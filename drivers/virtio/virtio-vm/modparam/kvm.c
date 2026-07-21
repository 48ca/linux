// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cache.h>

static bool __read_mostly enable_pmu = true;
module_param(enable_pmu, bool, 0444);

static int __read_mostly force_emulation_prefix;
module_param(force_emulation_prefix, int, 0444);

static bool __read_mostly eager_page_split = true;
module_param(eager_page_split, bool, 0444);

static bool __read_mostly tdp_mmu = true;
module_param(tdp_mmu, bool, 0444);

MODULE_LICENSE("GPL");
