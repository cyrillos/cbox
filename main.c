#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

#include "rb.h"
#include "assoc.h"

#define ARRAY_SIZE(__a) (sizeof(__a) / sizeof((__a)[0]))

#include "data.c"

#define TLM_MSEC_PER_SEC	1000L
#define TLM_USEC_PER_MSEC	1000L
#define TLM_NSEC_PER_USEC	1000L
#define TLM_NSEC_PER_MSEC	1000000L
#define TLM_USEC_PER_SEC	1000000L
#define TLM_NSEC_PER_SEC	1000000000L

static inline int64_t timespec_to_ns(struct timespec *ts)
{
	return ts->tv_sec * TLM_NSEC_PER_SEC + ts->tv_nsec;
}

#define DECLARE_ARGS(low, high)		unsigned long low, high
#define EAX_EDX_VAL(low, high)		((low) | (high) << 32)
#define EAX_EDX_RET(low, high)		"=a" (low), "=d" (high)
#define EAX_EDX_ECX_RET(low, high, ecx)	"=a" (low), "=c" (ecx), "=d" (high)

#define asm __asm__

static unsigned long long rdtsc_ordered(void)
{
	DECLARE_ARGS(low, high);

	asm volatile("lfence; rdtsc" : EAX_EDX_RET(low, high));

	return EAX_EDX_VAL(low, high);
}

static unsigned long long rdtscp(unsigned int *cpuid)
{
	DECLARE_ARGS(low, high);
	unsigned long ecx = -1;

	asm volatile("rdtscp" : EAX_EDX_ECX_RET(low, high, ecx));

	*cpuid = ecx;
	return EAX_EDX_VAL(low, high);
}

static int64_t read_clock(void)
{
	struct timespec ts;
	assert(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
	return timespec_to_ns(&ts);
}

static int64_t clock_start_val, clock_stop_val;

#define clock_start()	(long long)({ clock_start_val = read_clock(); clock_start_val; })
#define clock_stop()	(long long)({ clock_stop_val = read_clock(); clock_start_val; })
#define clock_diff()	(long long)(clock_stop_val - clock_start_val)

struct rlist {
	struct rlist *prev;
	struct rlist *next;
};

/**
 * Callable symbol bound to a module.
 */
struct module_sym {
	/**
	 * Anchor for module membership.
	 */
	struct rlist list;
	/**
	 * For C functions, address of the function.
	 */
	void *addr;
	/**
	 * Each stored function keeps a handle to the
	 * dynamic library for the C callback.
	 */
	void *module;
	/**
	 * Symbol (function) name definition.
	 */
	char *name;
};

struct cbox_func {
	/**
	 * Gather functions into rbtree.
	 */
	rb_node(struct cbox_func) nd;

	/**
	 * Symbol descriptor for the function in
	 * an associated module.
	 */
	struct module_sym mod_sym;

	/**
	 * Number of references to the function
	 * instance.
	 */
	ssize_t ref;

	/** Function name. */
	const char *name;

	/** Function name length. */
	size_t name_len;

	/** Function name keeper. */
	char inplace[0];
};

typedef rb_tree(struct cbox_func) func_rb_t;
static func_rb_t func_rb_root;

static int cbox_func_cmp(const struct cbox_func *a, const struct cbox_func *b)
{
	ssize_t len = (ssize_t)a->name_len - (ssize_t)b->name_len;
	if (len == 0)
		return strcmp(a->name, b->name);
	return len < 0 ? -1 : 1;
}

rb_gen(MAYBE_UNUSED static, func_rb_, func_rb_t,
       struct cbox_func, nd, cbox_func_cmp);

static struct cbox_func *cbox_func_find(const char *name, size_t name_len)
{
	struct cbox_func v = {
		.name		= name,
		.name_len	= name_len,
	};
	return func_rb_search(&func_rb_root, &v);
}

static struct cbox_func *cbox_func_new(const char *name, size_t name_len)
{
	const ssize_t cf_size = sizeof(struct cbox_func);
	ssize_t size = cf_size + name_len + 1;
	struct cbox_func *cf = malloc(size);
	assert(cf != NULL);

	cf->mod_sym.addr	= NULL;
	cf->mod_sym.module	= NULL;
	cf->ref			= 0;
	cf->mod_sym.name	= cf->inplace;
	cf->name		= cf->inplace;
	cf->name_len		= name_len;

	memcpy(cf->inplace, name, name_len);
	cf->inplace[name_len] = '\0';

	memset(&cf->nd, 0, sizeof(cf->nd));
	return cf;
}

static struct mh_strnptr_t *funcs_hash;

struct cbox_func_hash {
	/**
	 * Symbol descriptor for the function in
	 * an associated module.
	 */
	struct module_sym mod_sym;

	/**
	 * Number of references to the function
	 * instance.
	 */
	ssize_t ref;

	/** Function name. */
	const char *name;

	/** Function name length. */
	size_t name_len;

	/** Function name keeper. */
	char inplace[0];
};

static struct cbox_func_hash *cbox_func_hash_new(const char *name, size_t name_len)
{
	const ssize_t cf_size = sizeof(struct cbox_func);
	ssize_t size = cf_size + name_len + 1;
	struct cbox_func_hash *cf = malloc(size);
	assert(cf != NULL);

	cf->mod_sym.addr	= NULL;
	cf->mod_sym.module	= NULL;
	cf->ref			= 0;
	cf->mod_sym.name	= cf->inplace;
	cf->name		= cf->inplace;
	cf->name_len		= name_len;

	memcpy(cf->inplace, name, name_len);
	cf->inplace[name_len] = '\0';
	return cf;
}

static void run_rb_test(size_t nr_names)
{
	clock_start();
	func_rb_new(&func_rb_root);
	for (size_t i = 0; i < nr_names; i++) {
		struct cbox_func *cf = cbox_func_new(names[i], strlen(names[i]));
		func_rb_insert(&func_rb_root, cf);
	}
	clock_stop();
	printf("rb create diff : %20lld ns\n", clock_diff());

	clock_start();
	for (size_t i = 0; i < nr_names; i++) {
		struct cbox_func *cf = cbox_func_find(names[i], strlen(names[i]));
		assert(cf != NULL);
	}
	clock_stop();
	printf("rb lookup diff : %20lld ns\n", clock_diff());

#if 0
	printf("rb delete start: %20lld ns\n", clock_start());
	{
		struct cbox_func *cf = func_rb_first(&func_rb_root);
		while (cf != NULL) {
			func_rb_remove(&func_rb_root, cf);
			cf = func_rb_first(&func_rb_root);
		}
		func_rb_new(&func_rb_root);
	}
	printf("rb delete stop : %20lld ns\n", clock_stop());
	printf("rb delete diff : %20lld ns\n", clock_diff());
#endif
}

static void run_mh_test(size_t nr_names)
{
	clock_start();
	funcs_hash = mh_strnptr_new();
	assert(funcs_hash != NULL);
	for (size_t i = 0; i < nr_names; i++) {
		struct cbox_func_hash *cf = cbox_func_hash_new(names[i], strlen(names[i]));
		uint32_t name_hash = mh_strn_hash(cf->name, cf->name_len);
		const struct mh_strnptr_node_t strnode = {
			.str	= cf->name,
			.len	= cf->name_len,
			.hash	= name_hash,
			.val	= cf
		};

		assert(mh_strnptr_put(funcs_hash, &strnode, NULL, NULL) != mh_end(funcs_hash));
	}
	clock_stop();
	printf("mh create diff : %20lld ns\n", clock_diff());

	clock_start();
	for (size_t i = 0; i < nr_names; i++) {
		mh_int_t pos = mh_strnptr_find_inp(funcs_hash, names[i], strlen(names[i]));
		assert(pos != mh_end(funcs_hash));
	}
	clock_stop();
	printf("mh lookup diff : %20lld ns\n", clock_diff());
}

int main(int argc, char *argv[])
{
	size_t nr_names = ARRAY_SIZE(names);
	bool run_rb = false;
	bool run_mh = false;

#if 0
	for (unsigned i = 0; i < ARRAY_SIZE(name_vals); i++) {
		for (unsigned j = 0; j < strlen(name_vals[i]); j+=2) {
			printf("\\x%c%c", name_vals[i][j], name_vals[i][j+1]);
		}
		printf("\n");
	}
	return 0;
#endif

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--nr")) {
			if (i < argc-1) {
				nr_names = atoi(argv[i+1]);
				if (nr_names > ARRAY_SIZE(names)) {
					printf("too many elems, max %d\n",
					       (int)ARRAY_SIZE(names));
					return 1;
				}
				i++;
			} else {
				printf("max number of strings %d\n", (int)ARRAY_SIZE(names));
				return 1;
			}
		} else if (!strcmp(argv[i], "--rb")) {
			run_rb = true;
		} else if (!strcmp(argv[i], "--mh")) {
			run_mh = true;
		}
	}
	if (run_rb)
		run_rb_test(nr_names);
	if (run_mh)
		run_mh_test(nr_names);
	return 0;
}
