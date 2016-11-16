#ifndef AF_KTLS_OFFLOAD_H_
#define AF_KTLS_OFFLOAD_H_

#include <linux/types.h>

#include "af_ktls.h"

struct tls_record_info {
	struct list_head list;
	u32 end_seq;
	int len;
	int num_frags;
	skb_frag_t	frags[MAX_SKB_FRAGS];
};

struct ktls_key {
	char key[KTLS_AES_GCM_128_KEY_SIZE];
	char salt[KTLS_AES_GCM_128_SALT_SIZE];
	char iv[KTLS_AES_GCM_128_IV_SIZE];
};

struct ktls_keys {
	struct ktls_key tx;
	struct ktls_key rx;
};

struct ktls_offload_context {
	struct list_head records_list;
	struct tls_record_info *retransmit_hint;
	u32 expectedSN;
	spinlock_t lock; /* protects records list */
};

struct tls_record_info *ktls_get_record(
			struct ktls_offload_context *context,
			u32 seq);

int tls_sendmsg_with_offload(struct tls_sock *tsk, struct msghdr *msg,
		size_t size);

ssize_t tls_sendpage_with_offload(
		struct socket *sock, struct page *page,
		int offset, size_t size, int flags);

int tls_set_offload(struct socket *sock, char __user *src, size_t src_len);

#endif /* AF_KTLS_OFFLOAD_H_ */
