// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) Crackerjack Project., 2007-2008, Hitachi, Ltd
 * Copyright (c) 2017 Petr Vorel <pvorel@suse.cz>
 *
 * Authors:
 * Takahiro Yasui <takahiro.yasui.mp@hitachi.com>,
 * Yumiko Sugita <yumiko.sugita.yf@hitachi.com>,
 * Satoshi Fujiwara <sa-fuji@sdl.hitachi.co.jp>
 */

#include <errno.h>
#include <limits.h>

static int fd, fd_root, fd_nonblock, fd_maxint = INT_MAX - 1, fd_invalid = -1;

#include "mq_timed.h"

static struct tst_ts ts;
static void *bad_addr;

static struct test_case tcase[] = {
	{
		.fd = &fd,
		.send = 1,
	},
	{
		.fd = &fd,
		.len = 1,
		.send = 1,
	},
	{
		.fd = &fd,
		.len = MAX_MSGSIZE,
		.send = 1,
	},
	{
		.fd = &fd,
		.len = 1,
		.send = 1,
		.prio = MQ_PRIO_MAX - 1,
	},
	{
		.fd = &fd,
		.invalid_msg = 1,
		.send = 1,
		.ret = -1,
		.err = EMSGSIZE,
	},
	{
		.fd = &fd_invalid,
		.ret = -1,
		.err = EBADF,
	},
	{
		.fd = &fd_maxint,
		.ret = -1,
		.err = EBADF,
	},
	{
		.fd = &fd_root,
		.ret = -1,
		.err = EBADF,
	},
	{
		.fd = &fd_nonblock,
		.len = 16,
		.ret = -1,
		.err = EAGAIN,
	},
	{
		.fd = &fd,
		.len = 16,
		.tv_sec = -1,
		.rq = &ts,
		.ret = -1,
		.err = EINVAL,
	},
	{
		.fd = &fd,
		.len = 16,
		.tv_nsec = -1,
		.rq = &ts,
		.ret = -1,
		.err = EINVAL,
	},
	{
		.fd = &fd,
		.len = 16,
		.tv_nsec = 1000000000,
		.rq = &ts,
		.ret = -1,
		.err = EINVAL,
	},
	{
		.fd = &fd,
		.len = 16,
		.timeout = 1,
		.ret = -1,
		.rq = &ts,
		.err = ETIMEDOUT,
	},
	{
		.fd = &fd,
		.len = 16,
		.signal = 1,
		.rq = &ts,
		.ret = -1,
		.err = EINTR,
	},
	{
		.fd = &fd,
		.len = 16,
		.bad_ts_addr = 1,
		.ret = -1,
		.err = EFAULT,
	}
};

static void setup(void)
{
	struct time64_variants *tv = &variants[tst_variant];

	tst_res(TINFO, "Testing variant: %s", tv->desc);
	ts.type = tv->ts_type;

	bad_addr = tst_get_bad_addr(NULL);

	setup_common();
}

static void verify_mqt_receive(unsigned int i, pid_t pid)
{
	struct time64_variants *tv = &variants[tst_variant];
	const struct test_case *tc = &tcase[i];
	size_t len = MAX_MSGSIZE;
	char rmsg[MAX_MSGSIZE];
	void *abs_timeout;
	unsigned int j;
	unsigned int prio;

	if (tc->invalid_msg)
		len -= 1;

	if (tc->bad_ts_addr)
		abs_timeout = bad_addr;
	else
		abs_timeout = tst_ts_get(tc->rq);

	TEST(tv->mqt_receive(*tc->fd, rmsg, len, &prio, abs_timeout));

	if (pid > 0)
		kill_pid(pid);

	if (*tc->fd == fd)
		cleanup_queue(fd);

	if (TST_RET < 0) {
		if (tc->err != TST_ERR)
			tst_res(TFAIL | TTERRNO,
				"mq_timedreceive() failed unexpectedly, expected %s",
				tst_strerrno(tc->err));
		else
			tst_res(TPASS | TTERRNO, "mq_timedreceive() failed expectedly");

		return;
	}

	if ((long)tc->len != TST_RET) {
		tst_res(TFAIL, "mq_timedreceive() wrong length %ld, expected %u",
			TST_RET, tc->len);
		return;
	}

	if (tc->prio != prio) {
		tst_res(TFAIL, "mq_timedreceive() wrong prio %d, expected %d",
			prio, tc->prio);
		return;
	}

	for (j = 0; j < tc->len; j++) {
		if (rmsg[j] != smsg[j]) {
			tst_res(TFAIL,
				"mq_timedreceive() wrong data %d in %u, expected %d",
				rmsg[j], i, smsg[j]);
			return;
		}
	}

	tst_res(TPASS, "mq_timedreceive() returned %ld, priority %u, length: %zu",
			TST_RET, prio, len);
}

static void test_bad_addr(unsigned int i)
{
	struct time64_variants *tv = &variants[tst_variant];
	pid_t pid;
	int status;

	pid = SAFE_FORK();
	if (!pid) {
		verify_mqt_receive(i, pid);
		exit(0);
	}

	SAFE_WAITPID(pid, &status, 0);

	if (WIFEXITED(status) && !WEXITSTATUS(status))
		return;

	if (tv->ts_type == TST_LIBC_TIMESPEC &&
		WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV) {
		tst_res(TPASS, "Child killed by expected signal");
		return;
	}

	tst_res(TFAIL, "Child %s", tst_strstatus(status));
}

static void do_test(unsigned int i)
{
	struct time64_variants *tv = &variants[tst_variant];
	const struct test_case *tc = &tcase[i];
	pid_t pid = -1;

	tst_ts_set_sec(&ts, tc->tv_sec);
	tst_ts_set_nsec(&ts, tc->tv_nsec);

	if (tc->bad_ts_addr) {
		test_bad_addr(i);
		return;
	}

	if (tc->signal)
		pid = set_sig(tc->rq, tv->clock_gettime);

	if (tc->timeout)
		set_timeout(tc->rq, tv->clock_gettime);

	if (tc->send && tv->mqt_send(*tc->fd, smsg, tc->len, tc->prio, NULL) < 0) {
		tst_res(TFAIL | TTERRNO, "mq_timedsend() failed");
		return;
	}

	verify_mqt_receive(i, pid);
}

static struct tst_test test = {
	.tcnt = ARRAY_SIZE(tcase),
	.test = do_test,
	.test_variants = ARRAY_SIZE(variants),
	.setup = setup,
	.cleanup = cleanup_common,
	.forks_child = 1,
};
