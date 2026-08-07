/*
 * Copyright (c) 2002, Intel Corporation. All rights reserved.
 * Created by:  julie.n.fleischer REMOVE-THIS AT intel DOT com
 * This file is licensed under the GPL license.  For the full content
 * of this license, see the COPYING file at the top level of this
 * source tree.
 *
 * Test to see if timer_settime() sets errno = EINVAL if no timers have been
 * created yet.  Since this is a "may" assertion, either way is a pass.
 */

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include "posixtest.h"

#define BOGUSTID 9999

/*
 * when timerid argument does not correspond to a timer ID returned by
 * timer_create(), POSIX recommends EINVAL, but SIGSEGV is also
 * valid outcome.
 */
static void sigsegv_handler(int signum PTS_ATTRIBUTE_UNUSED)
{
	PTS_WRITE_MSG("Got SIGSEGV when calling timer_settime() with an invalid timer ID\n");
	PTS_WRITE_MSG("Test PASSED\n");
	_exit(PTS_PASS);
}

int test_main(int argc PTS_ATTRIBUTE_UNUSED, char **argv PTS_ATTRIBUTE_UNUSED)
{
	timer_t tid;
	struct itimerspec its;
	int tval = BOGUSTID;
	struct sigaction sa = { .sa_handler = sigsegv_handler };

	tid = (timer_t) & tval;

	sigfillset(&sa.sa_mask);
	sigaction(SIGSEGV, &sa, NULL);

	its.it_interval.tv_sec = 0;
	its.it_interval.tv_nsec = 0;
	its.it_value.tv_sec = 0;
	its.it_value.tv_nsec = 0;

	if (timer_settime(tid, 0, &its, NULL) == -1) {
		if (EINVAL == errno) {
			printf("fcn returned -1 and errno==EINVAL\n");
			return PTS_PASS;
		} else {
			printf("fcn returned -1, but errno!=EINVAL\n");
			printf("Test FAILED\n");
			return PTS_FAIL;
		}
	}
	printf("fcn did not return -1\n");
	return PTS_PASS;
}
