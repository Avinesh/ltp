// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2013 FNST, DAN LI <li.dan@cn.fujitsu.com>
 * Copyright (c) 2023 SUSE LLC Avinesh Kumar <avinesh.kumar@suse.com>
 */

/*\
 * [Description]
 *
 * Verify that, mmap() call with MAP_LOCKED flag successfully locks
 * the mapped pages into memory.
 */

#include <stdio.h>
#include "tst_test.h"

#define MMAPSIZE        (1UL<<16)
#define LINELEN         256

static char *addr;
static void getvmlck(unsigned int *lock_sz);

void getvmlck(unsigned int *lock_sz)
{
	char line[LINELEN];
	FILE *fp = NULL;

	fp = fopen("/proc/self/status", "r");
	if (fp == NULL)
		tst_brk(TFAIL | TERRNO, "could not open status file");

	while (fgets(line, LINELEN, fp) != NULL) {
		if (strstr(line, "VmLck") != NULL)
			break;
	}

	if (sscanf(line, "%*[^0-9]%d%*[^0-9]", lock_sz) != 1)
		tst_brk(TFAIL | TERRNO, "Get lock size failed");

	fclose(fp);
}

static void run(void)
{
	unsigned int sz_before, sz_after, sz_diff;

	getvmlck(&sz_before);

	addr = mmap(0, MMAPSIZE, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_LOCKED | MAP_ANONYMOUS, -1, 0);

	if (addr != MAP_FAILED)
		tst_res(TPASS, "mmap() with MAP_LOCKED flag passed");
	else {
		tst_res(TFAIL | TERRNO, "mmap() failed");
		return;
	}

	getvmlck(&sz_after);
	sz_diff = sz_after - sz_before;
	TST_EXP_EQ_LU(MMAPSIZE / 1024, sz_diff);

	SAFE_MUNMAP(addr, MMAPSIZE);
}

static struct tst_test test = {
	.test_all = run,
	.needs_tmpdir = 1
};
