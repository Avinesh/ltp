// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021 SUSE LLC Andrea Cervesato <andrea.cervesato@suse.com>
 */

/*\
 * Test if keyctl clear is correctly recognized by watch queue.
 */

#define _GNU_SOURCE

#include "tst_test.h"
#include "lapi/keyctl.h"
#include "common.h"

static void saw_key_cleared(struct watch_notification *n, size_t len,
                            unsigned int wtype)
{
	if (wqueue_key_event(n, len, wtype, NOTIFY_KEY_CLEARED))
		tst_res(TPASS, "keyctl clear has been recognized");
	else
		tst_res(TFAIL, "keyctl clear has not been recognized");
}

static void run(void)
{
	int fd;

	fd = wqueue_watch(256, &wqueue_filter);
	wqueue_add_key(fd);

	keyctl(KEYCTL_CLEAR, KEY_SPEC_SESSION_KEYRING);
	wqueue_consumer(fd, saw_key_cleared);

	SAFE_CLOSE(fd);
}

static struct tst_test test = {
	.test_all = run,
};
