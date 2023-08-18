// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2001
 *  07/2001 Ported by Wayne Boyer
 * Copyright (c) 2023 SUSE LLC Avinesh Kumar <avinesh.kumar@suse.com>
 */

/*\
 * [Description]
 *
 * Verify that, mmap() call with 'PROT_READ | PROT_EXEC; and file descriptor
 * which is open for read only and has read and execute permission bits set,
 * succeeds to map a file creating mapped memory with read/exec access.
 */

#include <stdlib.h>
#include "tst_test.h"

#define TEMPFILE "mmapfile"
static size_t page_sz;
static int fd;
static char *addr;
static char *dummy;

static void setup(void)
{
	char *tst_buf;

	page_sz = getpagesize();
	tst_buf = SAFE_CALLOC(page_sz, sizeof(char));
	memset(tst_buf, 'A', page_sz);

	fd = SAFE_OPEN(TEMPFILE, O_RDWR | O_CREAT, 0666);
	SAFE_WRITE(SAFE_WRITE_ALL, fd, tst_buf, page_sz);
	free(tst_buf);

	SAFE_FCHMOD(fd, 0555);
	SAFE_CLOSE(fd);

	fd = SAFE_OPEN(TEMPFILE, O_RDONLY);
	dummy = SAFE_CALLOC(page_sz, sizeof(char));
}

static void run(void)
{
	addr = mmap(0, page_sz, PROT_READ | PROT_EXEC, MAP_FILE | MAP_SHARED, fd, 0);

	if (addr == MAP_FAILED) {
		tst_res(TFAIL | TERRNO, "mmap() of %s failed", TEMPFILE);
		return;
	}

	SAFE_READ(1, fd, dummy, page_sz);
	SAFE_LSEEK(fd, 0, SEEK_SET);

	if (memcmp(dummy, addr, page_sz) == 0)
		tst_res(TPASS, "mmap() functionality successful");
	else
		tst_res(TFAIL, "mapped memory region contains invalid data");

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
