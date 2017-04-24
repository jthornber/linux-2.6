/*
 * Copyright (C) 2017 Red Hat. All rights reserved.
 *
 * This file is released under the GPL.
 */

#ifndef DM_UTILS_H
#define DM_UTILS_H

#include <linux/bio.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>

/*----------------------------------------------------------------*/

/*
 * Pulling common code from cache and thin into here for now.  Obviously
 * 'utils' isn't a good name.
 */

/*
 * Represents a chunk of future work.  'input' allows continuations to pass
 * values between themselves, typically error values.
 */
struct continuation {
	struct work_struct ws;
	int input;
};

static inline void init_continuation(struct continuation *k,
				     void (*fn)(struct work_struct *))
{
	INIT_WORK(&k->ws, fn);
	k->input = 0;
}

static inline void queue_continuation(struct workqueue_struct *wq,
				      struct continuation *k)
{
	queue_work(wq, &k->ws);
}

/*----------------------------------------------------------------*/

/*
 * The batcher collects together pieces of work that need a particular
 * operation to occur before they can proceed (typically a commit).
 */
struct batcher {
	/*
	 * The operation that everyone is waiting for.
	 */
	int (*commit_op)(void *context);
	void *commit_context;

	/*
	 * This is how bios should be issued once the commit op is complete
	 * (accounted_request).
	 */
	void (*issue_op)(struct bio *bio, void *context);
	void *issue_context;

	/*
	 * Queued work gets put on here after commit.
	 */
	struct workqueue_struct *wq;

	spinlock_t lock;
	struct list_head work_items;
	struct bio_list bios;
	struct work_struct commit_work;

	bool commit_scheduled;
};

void batcher_init(struct batcher *b,
		  int (*commit_op)(void *),
		  void *commit_context,
		  void (*issue_op)(struct bio *bio, void *),
		  void *issue_context,
		  struct workqueue_struct *wq);
void async_commit(struct batcher *b);
void continue_after_commit(struct batcher *b, struct continuation *k);

/*
 * Bios are errored if commit failed.
 */
void issue_after_commit(struct batcher *b, struct bio *bio);

/*
 * Call this if some urgent work is waiting for the commit to complete.
 */
void schedule_commit(struct batcher *b);

#endif
