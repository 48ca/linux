// SPDX-License-Identifier: GPL-2.0-or-later

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cache.h>

static bool __read_mostly avic;
module_param(avic, bool, 0444);

static bool __read_mostly npt = true;
module_param(npt, bool, 0444);

MODULE_LICENSE("GPL");
