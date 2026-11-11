/*
 * Copyright (c) 2002, Intel Corporation. All rights reserved.
 * Created by:  rolla.n.selbak REMOVE-THIS AT intel DOT com
 * This file is licensed under the GPL license.  For the full content
 * of this license, see the COPYING file at the top level of this
 * source tree.

 * Test that pthread_attr_setdetachstate()
 *
 * If the thread is created detached, then use of the ID of the newly created
 * thread by the pthread_detach() or pthread_join() function is an error.
 *
 * Steps:
 * 1.  Initialize a pthread_attr_t object using pthread_attr_init().
 * 2.  Using pthread_attr_setdetachstate(), set the detachstate to
 *     PTHREAD_CREATE_DETACHED.
 * 3.  Create a thread with this attribute. The thread blocks until released.
 * 4.  Call pthread_detach() and pthread_join() on this thread, it should give
 *     an error.
 * 5.  Release the thread.
 *
 * The thread must still be running while pthread_join() and pthread_detach()
 * are called. Once a detached thread has exited its ID is no longer valid, the
 * behavior of both calls is then undefined.
 */

#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include "posixtest.h"

static sem_t gate;

static void *a_thread_func()
{
	if (sem_wait(&gate) != 0)
		perror("sem_wait()");

	pthread_exit(0);
	return NULL;
}

int test_main(int argc PTS_ATTRIBUTE_UNUSED, char **argv PTS_ATTRIBUTE_UNUSED)
{
	pthread_t new_th;
	pthread_attr_t new_attr;
	int join_ret, detach_ret;

	if (sem_init(&gate, 0, 0) != 0) {
		perror("sem_init()");
		return PTS_UNRESOLVED;
	}

	/* Initialize attribute */
	if (pthread_attr_init(&new_attr) != 0) {
		perror("Cannot initialize attribute object\n");
		return PTS_UNRESOLVED;
	}

	/* Set the attribute object to PTHREAD_CREATE_DETACHED. */
	if (pthread_attr_setdetachstate(&new_attr, PTHREAD_CREATE_DETACHED) !=
	    0) {
		perror("Error in pthread_attr_setdetachstate()\n");
		return PTS_UNRESOLVED;
	}

	/* Create a new thread passing it the new attribute object */
	if (pthread_create(&new_th, &new_attr, a_thread_func, NULL) != 0) {
		perror("Error creating thread\n");
		return PTS_UNRESOLVED;
	}

	/*
	 * The thread cannot get past sem_wait() before the post below,
	 * so it is alive and detached.
	 */
	join_ret = pthread_join(new_th, NULL);
	detach_ret = pthread_detach(new_th);

	if (sem_post(&gate) != 0) {
		perror("sem_post()");
		return PTS_UNRESOLVED;
	}

	/* Both calls must fail with EINVAL. */
	if (join_ret != EINVAL) {
		printf("Test FAILED: pthread_join() returned '%s', expected EINVAL\n",
		       strerror(join_ret));
		return PTS_FAIL;
	}

	if (detach_ret != EINVAL) {
		printf("Test FAILED: pthread_detach() returned '%s', expected EINVAL\n",
		       strerror(detach_ret));
		return PTS_FAIL;
	}

	printf("Test PASSED\n");
	return PTS_PASS;
}
