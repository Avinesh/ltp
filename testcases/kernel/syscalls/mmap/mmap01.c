// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) International Business Machines  Corp., 2001
 *	07/2001 Ported by Wayne Boyer
 * Copyright (c) 2023 SUSE LLC Avinesh Kumar <avinesh.kumar@suse.com>
 */

/*\
 * [Description]
 *
 * Verify that, mmap() succeeds when used to map a file where size of the
 * file is not a multiple of the page size, the memory area beyond the end
 * of the file to the end of the page is accessible. Also, verify that
 * this area is all zeroed and the modifications done to this area are
 * not written to the file.
 */

#include <stdio.h>
#include <stdlib.h>
#include "tst_test.h"

#define TEMPFILE "mmapfile"
static int fd;
static size_t page_sz;
static size_t file_sz;
static char *dummy;
static char *addr;
static char cmd_buffer[BUFSIZ];

static void setup(void)
{
	struct stat stat_buf;
	char path_name[PATH_MAX];
	char write_buf[] = "hello world\n";

	SAFE_GETCWD(path_name, sizeof(path_name));

	fd = SAFE_OPEN(TEMPFILE, O_RDWR | O_CREAT, 0666);

	SAFE_WRITE(SAFE_WRITE_ALL, fd, write_buf, strlen(write_buf));
	SAFE_STAT(TEMPFILE, &stat_buf);

	file_sz = stat_buf.st_size;
	page_sz = getpagesize();

	dummy = SAFE_CALLOC(page_sz, sizeof(char));

	sprintf(cmd_buffer, "grep XYZ %s/%s > /dev/null", path_name, TEMPFILE);
}

static void run(void)
{
	addr = mmap(NULL, page_sz, PROT_READ | PROT_WRITE, MAP_FILE | MAP_SHARED, fd, 0);
	if (addr == MAP_FAILED) {
		tst_res(TFAIL | TERRNO, "mmap() of %s failed", TEMPFILE);
		return;
	}

	if (memcmp(&addr[file_sz], dummy, page_sz - file_sz) != 0)
		tst_brk(TFAIL, "mapped memory area contains invalid data");

	addr[file_sz] = 'X';
	addr[file_sz + 1] = 'Y';
	addr[file_sz + 2] = 'Z';

	if (msync(addr, page_sz, MS_SYNC) != 0)
		tst_brk(TFAIL | TERRNO, "failed to sync mapped file");

	if (system(cmd_buffer) != 0)
		tst_res(TPASS, "mmap() functionality successful");
	else
		tst_res(TFAIL, "mmap() functionality failed");

	memset(&addr[file_sz], 0, 3);
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
