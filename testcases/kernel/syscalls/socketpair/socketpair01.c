// SPDX-License-Identifier: GPL-2.0-or-later
/*
* Copyright (c) International Business Machines Corp., 2001
* Copyright (c) Linux Test Project, 2003-2022
*/

/*\
 * Verify that socketpair(2) fails and set proper errno
 *
 * - EAFNOSUPPORT on invalid domain
 * - EINVAL on invalid type
 * - EPROTONOSUPPORT on raw open as non-root
 * - EFAULT on bad aligned pointer
 * - EFAULT on bad unaligned pointer
 * - EOPNOTSUPP on UDP socket
 * - EPROTONOSUPPORT on TCP dgram
 * - EOPNOTSUPP on TCP socket
 * - EPROTONOSUPPORT on ICMP stream
 *
 * Also test creating UNIX domain dgram.
 */

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include "tst_test.h"

static int fds[2];

struct test_case_t {
	int domain;
	int type;
	int proto;
	int *sv;
	int retval;
	int experrno;
	char *desc;
} tdat[] = {
	{0, SOCK_STREAM, 0, fds, -1, EAFNOSUPPORT, "invalid domain"},
	{PF_INET, 75, 0, fds, -1, EINVAL, "invalid type"},
	{PF_UNIX, SOCK_DGRAM, 0, fds, 0, 0, "UNIX domain dgram"},
	{PF_INET, SOCK_RAW, 0, fds, -1, EPROTONOSUPPORT, "raw open as non-root"},
	{PF_UNIX, SOCK_STREAM, 0, 0, -1, EFAULT, "bad aligned pointer"},
	{PF_UNIX, SOCK_STREAM, 0, (int *)7, -1, EFAULT, "bad unaligned pointer"},
	{PF_INET, SOCK_DGRAM, 17, fds, -1, EOPNOTSUPP, "UDP socket"},
	{PF_INET, SOCK_DGRAM, 6, fds, -1, EPROTONOSUPPORT, "TCP dgram"},
	{PF_INET, SOCK_STREAM, 6, fds, -1, EOPNOTSUPP, "TCP socket"},
	{PF_INET, SOCK_STREAM, 1, fds, -1, EPROTONOSUPPORT, "ICMP stream"}
};

static void verify_socketpair(unsigned int n)
{
	struct test_case_t *tc = &tdat[n];

	TEST(socketpair(tc->domain, tc->type, tc->proto, tc->sv));

	if (TST_RET == 0) {
		SAFE_CLOSE(fds[0]);
		SAFE_CLOSE(fds[1]);
	}

	if (TST_RET != tc->retval) {
		tst_res(TFAIL, "%s returned %ld (expected %d)",
			tc->desc, TST_RET, tc->retval);
		return;
	}

	if (TST_ERR != tc->experrno) {
		tst_res(TFAIL | TTERRNO, "expected %s(%d)",
		        tst_strerrno(tc->experrno), tc->experrno);
		return;
	}

	tst_res(TPASS, "%s successful", tc->desc);
}

static struct tst_test test = {
	.tcnt = ARRAY_SIZE(tdat),
	.test = verify_socketpair
};
