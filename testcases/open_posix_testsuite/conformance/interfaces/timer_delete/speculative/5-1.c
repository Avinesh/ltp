/*
 * Copyright (c) 2002, Intel Corporation. All rights reserved.
 * Created by:  julie.n.fleischer REMOVE-THIS AT intel DOT com
 * This file is licensed under the GPL license.  For the full content
 * of this license, see the COPYING file at the top level of this
 * source tree.

 * Test to see if timer_delete() returns -1 and sets errno==EINVAL if
 * timerid is not a valid timer ID or not.
 * Since this is a "may" requirement, either option is a PASS.
 */

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "posixtest.h"

#define BOGUSTIMERID 99999

/*
 * when timerid argument does not correspond to a timer ID returned by
 * timer_create(), POSIX recommends EINVAL, but SIGSEGV is also
 * valid outcome.
 */
static void sigsegv_handler(int signum PTS_ATTRIBUTE_UNUSED)
{
	PTS_WRITE_MSG("Got SIGSEGV when calling timer_delete() with an invalid timer ID\n");
	PTS_WRITE_MSG("Test PASSED\n");
	_exit(PTS_PASS);
}

int test_main(int argc PTS_ATTRIBUTE_UNUSED, char **argv PTS_ATTRIBUTE_UNUSED)
{
	timer_t tid;
	int tval = BOGUSTIMERID;
	struct sigaction sa = { .sa_handler = sigsegv_handler };

	tid = (timer_t) & tval;

	sigfillset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, NULL);

	if (timer_delete(tid) == -1) {
		if (errno == EINVAL) {
			printf
			    ("timer_delete() returned -1 and set errno=EINVAL\n");
			return PTS_PASS;
		} else {
			printf
			    ("timer_delete() returned -1, but didn't set errno!=EINVAL\n");
			return PTS_FAIL;
		}
	}

	printf("timer_delete() did not return -1\n");
	return PTS_PASS;
}
