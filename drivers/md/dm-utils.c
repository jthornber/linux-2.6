#include "dm-utils.h"

#include <linux/bio.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/jiffies.h>
#include <linux/init.h>
#include <linux/mempool.h>
#include <linux/module.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>

static void __commit(struct work_struct *_ws)
{
	struct batcher *b = container_of(_ws, struct batcher, commit_work);

	int r;
	unsigned long flags;
	struct list_head work_items;
	struct work_struct *ws, *tmp;
	struct continuation *k;
	struct bio *bio;
	struct bio_list bios;

	INIT_LIST_HEAD(&work_items);
	bio_list_init(&bios);

	/*
	 * We have to grab these before the commit_op to avoid a race
	 * condition.
	 */
	spin_lock_irqsave(&b->lock, flags);
	list_splice_init(&b->work_items, &work_items);
	bio_list_merge(&bios, &b->bios);
	bio_list_init(&b->bios);
	b->commit_scheduled = false;
	spin_unlock_irqrestore(&b->lock, flags);

	r = b->commit_op(b->commit_context);

	list_for_each_entry_safe(ws, tmp, &work_items, entry) {
		k = container_of(ws, struct continuation, ws);
		k->input = r;
		INIT_LIST_HEAD(&ws->entry); /* to avoid a WARN_ON */
		queue_work(b->wq, ws);
	}

	while ((bio = bio_list_pop(&bios))) {
		if (r) {
			bio->bi_error = r;
			bio_endio(bio);
		} else
			b->issue_op(bio, b->issue_context);
	}
}

void batcher_init(struct batcher *b,
			 int (*commit_op)(void *),
			 void *commit_context,
			 void (*issue_op)(struct bio *bio, void *),
			 void *issue_context,
			 struct workqueue_struct *wq)
{
	b->commit_op = commit_op;
	b->commit_context = commit_context;
	b->issue_op = issue_op;
	b->issue_context = issue_context;
	b->wq = wq;

	spin_lock_init(&b->lock);
	INIT_LIST_HEAD(&b->work_items);
	bio_list_init(&b->bios);
	INIT_WORK(&b->commit_work, __commit);
	b->commit_scheduled = false;
}

void async_commit(struct batcher *b)
{
	queue_work(b->wq, &b->commit_work);
}

void continue_after_commit(struct batcher *b, struct continuation *k)
{
	unsigned long flags;
	bool commit_scheduled;

	spin_lock_irqsave(&b->lock, flags);
	commit_scheduled = b->commit_scheduled;
	list_add_tail(&k->ws.entry, &b->work_items);
	spin_unlock_irqrestore(&b->lock, flags);

	if (commit_scheduled)
		async_commit(b);
}

/*
 * Bios are errored if commit failed.
 */
void issue_after_commit(struct batcher *b, struct bio *bio)
{
       unsigned long flags;
       bool commit_scheduled;

       spin_lock_irqsave(&b->lock, flags);
       commit_scheduled = b->commit_scheduled;
       bio_list_add(&b->bios, bio);
       spin_unlock_irqrestore(&b->lock, flags);

       if (commit_scheduled)
	       async_commit(b);
}

/*
 * Call this if some urgent work is waiting for the commit to complete.
 */
void schedule_commit(struct batcher *b)
{
	bool immediate;
	unsigned long flags;

	spin_lock_irqsave(&b->lock, flags);
	immediate = !list_empty(&b->work_items) || !bio_list_empty(&b->bios);
	b->commit_scheduled = true;
	spin_unlock_irqrestore(&b->lock, flags);

	if (immediate)
		async_commit(b);
}

