// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2001
 *  07/2001 Ported by Wayne Boyer
 * Copyright (c) 2023 SUSE LLC Avinesh Kumar <avinesh.kumar@suse.com>
 */

/*\
 * [Description]
 *
 * Verify that, mmap() call with PROT_READ and a file descriptor which is
 * open for read only, succeeds to map a file creating mapped memory with
 * read access.
 */

#include <stdlib.h>
#include <stdio.h>
#include "tst_test.h"

#define TEMPFILE "mmapfile"
static ssize_t page_sz;
static int fd;
static char *addr;
static char *dummy;

static void setup(void)
{
	char *buf;

	page_sz = getpagesize();
	buf = SAFE_CALLOC(page_sz, sizeof(char));
	memset(buf, 'A', page_sz);

	fd = SAFE_OPEN(TEMPFILE, O_RDWR | O_CREAT, 0666);
	SAFE_WRITE(SAFE_WRITE_ALL, fd, buf, page_sz);
	free(buf);
	SAFE_FCHMOD(fd, 0444);
	SAFE_CLOSE(fd);

	fd = SAFE_OPEN(TEMPFILE, O_RDONLY);
	dummy = SAFE_CALLOC(page_sz, sizeof(char));
}

static void run(void)
{
	addr = mmap(0, page_sz, PROT_READ, MAP_FILE | MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		tst_res(TFAIL | TERRNO, "mmap() of %s failed", TEMPFILE);
		return;
	}

	SAFE_READ(1, fd, dummy, page_sz);
	SAFE_LSEEK(fd, 0, SEEK_SET);

	if (memcmp(dummy, addr, page_sz) == 0)
		tst_res(TPASS, "mmap() functionality successful");
	else
		tst_res(TFAIL, "mapped memory area contains invalid data");

	SAFE_MUNMAP(addr, page_sz);
}

static void cleanup(void)
{
	if (fd > 0)
		SAFE_CLOSE(fd);
	if (dummy)
		free(dummy);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test_all = run,
	.needs_tmpdir = 1
};
