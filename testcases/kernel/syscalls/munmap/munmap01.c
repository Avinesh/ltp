// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2001
 *  07/2001 Ported by Wayne Boyer
 * Copyright (c) 2023 SUSE LLC Avinesh Kumar <avinesh.kumar@suse.com>
 */

/*\
 * [Description]
 *
 * Verify that, munmap() call successfully unmaps a mapped region from a
 * file mapping, and any attempt to access the unmapped region generates
 * SIGSEGV signal.
 */

#include "tst_test.h"
#include <setjmp.h>

#define TEMPFILE "mmapfile"
static char *addr;
static int fd;
static volatile int sig_flag;
static sigjmp_buf env;
static size_t page_sz;

static void sig_handler(int sig)
{
	if (sig == SIGSEGV) {
		sig_flag = 1;
		siglongjmp(env, 1);
	}
}

static void setup(void)
{
	SAFE_SIGNAL(SIGSEGV, sig_handler);

	page_sz = getpagesize();
	fd = SAFE_OPEN(TEMPFILE, O_RDWR | O_CREAT, 0666);

	SAFE_LSEEK(fd, page_sz * 2, SEEK_SET);
	SAFE_WRITE(SAFE_WRITE_ALL, fd, "a", 1);
}

static void run(void)
{
	addr = SAFE_MMAP(NULL, page_sz, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);

	TST_EXP_PASS(munmap(addr, page_sz));
	if (TST_RET == -1)
		return;

	if (sigsetjmp(env, 1) == 0)
		*addr = 50;

	if (sig_flag == 1)
		tst_res(TPASS, "Received SIGSEGV signal");
	else
		tst_res(TFAIL, "SIGSEGV signal not received");

	sig_flag = 0;
}

static void cleanup(void)
{
	if (fd > 0)
		SAFE_CLOSE(fd);
}

static struct tst_test test = {
	.setup = setup,
	.cleanup = cleanup,
	.test_all = run,
	.needs_tmpdir = 1
};
