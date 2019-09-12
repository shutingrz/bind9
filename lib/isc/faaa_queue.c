#include <stdalign.h>

#include <isc/atomic.h>
#include <isc/string.h>
#include <isc/mem.h>
#include <isc/hp.h>

#define BUFFER_SIZE 1024

#define MAX_THREADS 128

static uintptr_t taken_uint = UINTPTR_MAX;;

typedef struct node {
	atomic_uint_fast32_t deqidx;
	atomic_uintptr_t items[BUFFER_SIZE];
	atomic_uint_fast32_t enqidx;
	atomic_uintptr_t next;
	isc_mem_t *mctx;
} node_t;

/* we just need one Hazard Pointer */
#define HP_TAIL 0
#define HP_HEAD 0

struct isc_faaa_queue {
	alignas(128) atomic_uintptr_t head;
	alignas(128) atomic_uintptr_t tail;
	isc_mem_t *mctx;
	int max_threads;
	uintptr_t *taken;
	isc_hp_t *hp;
};

typedef struct isc_faaa_queue isc_faaa_queue_t;

static node_t *
node_new(isc_mem_t *mctx, uintptr_t item) {
	node_t *node = isc_mem_get(mctx, sizeof(*node));
	*node = (node_t){
		.deqidx = 0,
		.enqidx = 1,
		.next = 0,
		.items = { item, 0 }
	};
	isc_mem_attach(mctx, &node->mctx);
	return (node);
}

static void
node_destroy(void *node0) {
	node_t *node = (node_t *)node0;
	isc_mem_putanddetach(&node->mctx, node, sizeof(*node));
}

static bool
node_cas_next(atomic_uintptr_t node, uintptr_t cmp, const node_t *val) {
	return (atomic_compare_exchange_strong(&node, &cmp, (uintptr_t)val));
}

bool
queue_cas_tail(isc_faaa_queue_t *queue, uintptr_t cmp, const node_t *val) {
	return (atomic_compare_exchange_strong(&queue->tail, &cmp, (uintptr_t)val));
}

bool
queue_cas_head(isc_faaa_queue_t *queue, uintptr_t cmp, const node_t *val) {
	return (atomic_compare_exchange_strong(&queue->head, &cmp, (uintptr_t)val));
}

isc_faaa_queue_t *
isc_faaa_queue_new(isc_mem_t *mctx, int max_threads) {
	isc_faaa_queue_t *queue = isc_mem_get(mctx, sizeof(*queue));
	node_t *sentinel = node_new(mctx, (uintptr_t)NULL);

	if (max_threads == 0) {
		max_threads = MAX_THREADS;
	}

	*queue = (isc_faaa_queue_t){
		.max_threads = max_threads,
		.taken = &taken_uint,
	};

	isc_mem_attach(mctx, &queue->mctx);

	queue->hp = isc_hp_new(mctx, 0, max_threads, node_destroy);

	atomic_init(&sentinel->enqidx, 0);
	atomic_init(&queue->head, (uintptr_t)sentinel);
	atomic_init(&queue->tail, (uintptr_t)sentinel);

	return (queue);
}

uintptr_t
isc_faaa_queue_dequeue(isc_faaa_queue_t *queue, const int tid);

void
isc_faaa_queue_destroy(isc_faaa_queue_t *queue) {
	node_t *last;

	while (isc_faaa_queue_dequeue(queue, 0) != (uintptr_t)NULL);
	last = (node_t *)atomic_load_relaxed(&queue->head);
	node_destroy(last);
	isc_hp_destroy(queue->hp);
	isc_mem_putanddetach(&queue->mctx, queue, sizeof(*queue));
}
