// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2001
 *  04/2003 Written by Paul Larson
 * Copyright (c) 2023 SUSE LLC Avinesh Kumar <avinesh.kumar@suse.com>
 */

/*\
 * [Description]
 *
 * Verify that, once we have a file mapping created using mmap(), we can
 * successfully shrink, grow or zero the size of the mapped file using
 * ftruncate.
 */


#include <stdlib.h>
#include "tst_test.h"

#define mapsize (1 << 14)
#define TEMPFILE "mmapfile"
static int fd;
static char *addr;

static struct tcase {
	off_t newsize;
	char *desc;
} tcases[] = {
	{mapsize - 8192, "ftruncate mapped file to a smaller size"},
	{mapsize + 1024, "ftruncate mapped file to a bigger size"},
	{0, "ftruncate mapped file to zero size"}
};

static void setup(void)
{
	fd = SAFE_OPEN(TEMPFILE, O_RDWR | O_CREAT, 0666);

	SAFE_FTRUNCATE(fd, mapsize);

	addr = mmap(0, mapsize, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED)
		tst_brk(TFAIL | TERRNO, "mmap() failed");

	memset(addr, 'A', mapsize);

}

static void run(unsigned int i)
{
	struct stat stat_buf;
	struct tcase *tc = &tcases[i];

	TST_EXP_PASS(ftruncate(fd, tc->newsize), "%s", tc->desc);

	SAFE_FSTAT(fd, &stat_buf);
	TST_EXP_EQ_LI(stat_buf.st_size, tc->newsize);

	SAFE_FTRUNCATE(fd, mapsize);
}

static void cleanup(void)
{
	if (fd > 0)
		SAFE_CLOSE(fd);
	if (addr)
		SAFE_MUNMAP(addr, mapsize);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test = run,
	.tcnt = ARRAY_SIZE(tcases),
	.needs_tmpdir = 1
};
