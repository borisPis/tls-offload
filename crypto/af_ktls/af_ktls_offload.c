#include <net/tcp.h>
#include <net/inet_common.h>

#include "af_ktls_offload.h"

static void tls_destroy_record(struct tls_record_info *record)
{
	skb_frag_t *frag;

	while (record->num_frags > 0) {
		record->num_frags--;
		frag = &record->frags[record->num_frags];
		__skb_frag_unref(frag);
	}
	kfree(record);
}

static void clean_offloaded_data(struct sock *sk)
{
	struct ktls_offload_context *context = sk->sk_tls_offload;
	struct tcp_sock *tp = tcp_sk(sk);
	struct tls_record_info *info, *temp;
	unsigned long flags;

	spin_lock_irqsave(&context->lock, flags);
	info = context->retransmit_hint;
	if (info &&
	    !before(tp->snd_una, info->end_seq)) {
		context->retransmit_hint = NULL;
		list_del(&info->list);
		tls_destroy_record(info);
	}

	list_for_each_entry_safe(info, temp, &context->records_list, list) {
		if (before(tp->snd_una, info->end_seq))
			break;
		list_del(&info->list);

		tls_destroy_record(info);
	}

	spin_unlock_irqrestore(&context->lock, flags);
}

static void delete_all_records(struct sock *sk)
{
	struct ktls_offload_context *context = sk->sk_tls_offload;
	struct tls_record_info *info, *temp;

	list_for_each_entry_safe(info, temp, &context->records_list, list) {
		list_del(&info->list);
		tls_destroy_record(info);
	}
}

struct tls_record_info *ktls_get_record(
			struct ktls_offload_context *context,
			u32 seq) {
	struct tls_record_info *info;

	info = context->retransmit_hint;
	if (!info ||
	    before(seq, info->end_seq - info->len))
		info = list_first_entry(&context->records_list,
					struct tls_record_info, list);

	list_for_each_entry_from(info, &context->records_list, list) {
		if (before(seq, info->end_seq)) {
			context->retransmit_hint = info;
			return info;
		}
	}

	return NULL;
}
EXPORT_SYMBOL(ktls_get_record);

static int tls_send_record(struct sock *sk, struct tls_record_info *record)
{
	struct ktls_offload_context *context = sk->sk_tls_offload;
	struct tcp_sock *tp = tcp_sk(sk);
	int i = 0;
	skb_frag_t *frag;
	int flags = MSG_SENDPAGE_NOTLAST;
	int ret = 0;

	record->end_seq = tp->write_seq + record->len;

	spin_lock_irq(&context->lock);
	list_add_tail(&record->list, &context->records_list);
	spin_unlock_irq(&context->lock);

	while (flags == MSG_SENDPAGE_NOTLAST) {
		frag = &record->frags[i];

		i++;
		if (i == record->num_frags)
			flags = 0;
		ret = sk->sk_socket->ops->sendpage(sk->sk_socket,
						   skb_frag_page(frag),
						   frag->page_offset,
						   skb_frag_size(frag),
						   flags);

		if (ret != skb_frag_size(frag)) {
			pr_err("do_tcp_sendpages sent only part of the frag ret=%d",
			       ret);
		}
	}

	pr_info("new record added %u\n", record->end_seq);
	return ret;
}

int tls_sendmsg_with_offload(struct tls_sock *tsk, struct msghdr *msg,
		size_t size)
{
	struct sock *sk = tsk->socket->sk;
	struct tls_record_info *record;
	int create_header = 1;
	int ret = 0;
	int copy;
	skb_frag_t *frag;
	struct page_frag *pfrag;
	void *buf;

	record = kmalloc(sizeof(*record), GFP_KERNEL);
	if (!record)
		return -ENOMEM;

	record->len = size + KTLS_TLS_OVERHEAD;
	record->num_frags = 0;

	pfrag = &current->task_frag;
	do {
		if (!skb_page_frag_refill(KTLS_TLS_PREPEND_SIZE, pfrag,
					  GFP_KERNEL)) {
			ret = -ENOMEM;
			break;
		}

		get_page(pfrag->page);
		frag = &record->frags[record->num_frags];
		__skb_frag_set_page(frag, pfrag->page);
		frag->page_offset = pfrag->offset;
		skb_frag_size_set(frag, 0);
		record->num_frags++;
		buf = skb_frag_address(frag);

		if (create_header) {
			create_header = 0;
			tls_make_prepend(tsk, buf, size);


			skb_frag_size_add(frag, KTLS_TLS_PREPEND_SIZE);

			pfrag->offset += KTLS_TLS_PREPEND_SIZE;
			buf += KTLS_TLS_PREPEND_SIZE;

			if (!size)
				break;
		}


		copy = min_t(int, size, pfrag->size - pfrag->offset);
		if (copy_from_iter_nocache(
				buf,
				copy, &msg->msg_iter) != copy) {
			ret = -EFAULT;
			break;
		}

		skb_frag_size_add(frag, copy);
		pfrag->offset += copy;

		size -= copy;
	} while (size);

	if (ret) {
		tls_destroy_record(record);
		return ret;
	}

	frag = &record->frags[record->num_frags];
	__skb_frag_set_page(frag, ZERO_PAGE(0));
	frag->page_offset = 0;
	skb_frag_size_set(frag, KTLS_TAG_SIZE);
	__skb_frag_ref(frag);
	record->num_frags++;

	ret = tls_send_record(sk, record);
	if (ret)
		tls_increment_seqno(tsk->iv_send, tsk);

	return ret;
}
EXPORT_SYMBOL(tls_sendmsg_with_offload);

static int tls_create_record_for_sendpage(struct tls_sock *tsk,
					  struct tls_record_info *record)
{
	struct page_frag *pfrag;
	void *buf;
	skb_frag_t *frag;

	pfrag = &current->task_frag;
	if (!skb_page_frag_refill(KTLS_TLS_PREPEND_SIZE, pfrag, GFP_KERNEL))
		return -ENOMEM;

	get_page(pfrag->page);
	frag = &record->frags[0];
	__skb_frag_set_page(frag, pfrag->page);
	frag->page_offset = pfrag->offset;
	skb_frag_size_set(frag, KTLS_TLS_PREPEND_SIZE);
	buf = skb_frag_address(frag);

	tls_make_prepend(tsk, buf, record->len);
	pfrag->offset += KTLS_TLS_PREPEND_SIZE;
	frag = &record->frags[record->num_frags];
	__skb_frag_set_page(frag, ZERO_PAGE(0));
	frag->page_offset = 0;
	skb_frag_size_set(frag, KTLS_TAG_SIZE);
	__skb_frag_ref(frag);
	record->num_frags++;
	record->len += KTLS_TLS_OVERHEAD;

	return 0;
}

static ssize_t tls_close_record(struct tls_sock *tsk)
{
	int ret;
	struct tls_record_info *record;
	struct sock *sk = tsk->socket->sk;

	record = tsk->record;

	ret = tls_create_record_for_sendpage(tsk, record);
	if (ret) {
		goto do_sendmsg_end;
	};

	ret = tls_send_record(sk, record);
	if (ret > 0)
		tls_increment_seqno(tsk->iv_send, tsk);

	tsk->record = NULL;

do_sendmsg_end:
	return ret;
}

ssize_t tls_sendpage_with_offload(
		struct socket *sock, struct page *page,
		int offset, size_t size, int flags)
{
	int ret = 0;
	struct tls_sock *tsk = tls_sk(sock->sk);
	struct tls_record_info *record;
	skb_frag_t *frag;
	size_t frag_leftover;
	size_t orig_size = size;

	while (size && (ret >= 0)) {
		record = tsk->record;
		if (!record) {
			record = kmalloc(sizeof(*record), GFP_KERNEL);
			tsk->record = record;
			if (!record) {
				ret =  -ENOMEM;
				break;
			}
			/* reserving place for header */
			record->num_frags = 1;
			record->len = 0;
		}

		get_page(page);
		frag = &record->frags[record->num_frags];
		__skb_frag_set_page(frag, page);
		frag->page_offset = offset;
		skb_frag_size_set(frag, size);
		record->num_frags++;
		record->len += size;
		/*TODO: optimization: if page == prev. page -
		 * do not consume new frag and update offset + size. see
		 * TCP_sendpage for similar optimizations
		 */

		if (record->len > KTLS_MAX_PAYLOAD_SIZE) {
			frag_leftover = record->len - KTLS_MAX_PAYLOAD_SIZE;
			skb_frag_size_sub(frag, frag_leftover);
			record->len -= frag_leftover;
			offset += frag->size;
		}

		if ((record->len >= KTLS_MAX_PAYLOAD_SIZE)  ||
		    (record->num_frags + 1 >= MAX_SKB_FRAGS) ||
		    (!(flags & MSG_SENDPAGE_NOTLAST))) {
			ret = tls_close_record(tsk);
		}
		size -= frag->size;
	}

	return ret < 0 ? ret : (orig_size - size);
}
EXPORT_SYMBOL(tls_sendpage_with_offload);

/* We assume that the socket is already connected */
static struct net_device *get_netdevice_for_socket(struct sock *sk)
{
	struct inet_sock *inet = inet_sk(sk);
	struct net_device *netdev = NULL;

	pr_info("Using output interface 0x%x\n", inet->cork.fl.flowi_oif);
	netdev = dev_get_by_index(sock_net(sk), inet->cork.fl.flowi_oif);

	return netdev;
}

static int attach_sock_to_netdev(struct sock *sk, struct ktls_keys *keys,
		struct ktls_offload_context **context)
{
	struct net_device *netdev = get_netdevice_for_socket(sk);
	int ret = -EINVAL;

	if (!netdev) {
		pr_err("attach_sock_to_netdev: netdev not found\n");
		return -EINVAL;
	}

	if (!netdev->ktls_ops) {
		pr_err("attach_sock_to_netdev: netdev %s with no TLS offload\n",
				netdev->name);
		goto out;
	}

	ret = netdev->ktls_ops->ktls_dev_add(netdev, sk, keys, context);
	if (ret) {
		pr_err("The netdev has refused to offload this socket\n");
		goto out;
	}

	lock_sock(sk);
	sk->sk_bound_dev_if = netdev->ifindex;
	sk_dst_reset(sk);
	release_sock(sk);

	ret = 0;
out:
	dev_put(netdev);
	return ret;
}

static void tls_offload_cleanup(struct sock *sk)
{
	struct net_device *netdev;

	if (!sk->sk_tls_offload)
		return;

	netdev = get_netdevice_for_socket(sk);
	if (!netdev) {
		pr_err("got offloaded socket with no netdev");
		return;
	}

	delete_all_records(sk);

	netdev->ktls_ops->ktls_dev_del(netdev, sk);
	dev_put(netdev);
	inet_sock_destruct(sk);
}

static void get_ktls_keys(struct tls_sock *tsk, struct ktls_keys *keys)
{
	memcpy(keys->tx.key, tsk->key_send.key, sizeof(keys->tx.key));
	memcpy(keys->tx.salt, tsk->key_send.salt, sizeof(keys->tx.salt));
	memcpy(keys->tx.iv, tsk->iv_send, sizeof(keys->tx.iv));

	memcpy(keys->rx.key, tsk->key_recv.key, sizeof(keys->tx.key));
	memcpy(keys->rx.salt, tsk->key_recv.salt, sizeof(keys->tx.salt));
	memcpy(keys->rx.iv, tsk->iv_recv, sizeof(keys->tx.iv));
}

int tls_set_offload(struct socket *sock, char __user *src, size_t src_len)
{
	int ret;
	uint32_t offload;
	struct tls_sock *tsk;
	struct socket *offloaded_sock;
	struct ktls_keys keys;
	struct ktls_offload_context *context;

	tsk = tls_sk(sock->sk);

	if (src_len != sizeof(offload))
		return -EBADMSG;

	ret = copy_from_user(&offload, src, sizeof(offload));
	if (ret)
		return -EFAULT;

	if (!offload)
		return -EINVAL;

	if (!KTLS_SEND_READY(tsk))
		return -EINVAL;

	if (!KTLS_RECV_READY(tsk))
		return -EINVAL;

	offloaded_sock = tsk->socket;

	/* verify it is a tcp socket */
	if (offloaded_sock->type != SOCK_STREAM) {
		pr_err("Bad socket type - expected SOCK_STREAM\n");
		return -EINVAL;
	}

	get_ktls_keys(tsk, &keys);

	ret = attach_sock_to_netdev(offloaded_sock->sk, &keys, &context);
	if (ret)
		return ret;

	spin_lock_init(&context->lock);
	INIT_LIST_HEAD(&context->records_list);

	offloaded_sock->sk->sk_tls_offload = context;

	/* Olffload can be disabled only after the real socket is destroyed. */
	offloaded_sock->sk->sk_destruct = tls_offload_cleanup;

	inet_csk(offloaded_sock->sk)->icsk_clean_acked =
		&clean_offloaded_data;

	return 0;
}
EXPORT_SYMBOL(tls_set_offload);
