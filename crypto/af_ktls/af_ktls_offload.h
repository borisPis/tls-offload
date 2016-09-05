#ifndef AF_KTLS_OFFLOAD_H_
#define AF_KTLS_OFFLOAD_H_

#include <linux/types.h>

struct tls_record_info {
	struct list_head list;
	u32 start_seq;
	int len;
	int num_frags;
	skb_frag_t	frags[MAX_SKB_FRAGS];
};
#endif /* AF_KTLS_OFFLOAD_H_ */
