/*
 * af_ktls: TLS/DTLS socket
 *
 * Copyright (C) 2016
 *
 * Original authors:
 *   Fridolin Pokorny <fpokorny@redhat.com>
 *   Nikos Mavrogiannopoulos <nmav@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 */

#ifndef AF_KTLS_H_
#define AF_KTLS_H_

#include <linux/types.h>
#include <crypto/if_alg.h>
#include <net/strparser.h>

#define PF_KTLS				12
#define AF_KTLS				PF_KTLS

/* getsockopt() optnames */
#define KTLS_SET_IV_RECV		1
#define KTLS_SET_KEY_RECV		2
#define KTLS_SET_SALT_RECV		3
#define KTLS_SET_IV_SEND		4
#define KTLS_SET_KEY_SEND		5
#define KTLS_SET_SALT_SEND		6
#define KTLS_SET_MTU			7
#define KTLS_UNATTACH			8
#define KTLS_SET_OFFLOAD		9

/* setsockopt() optnames */
#define KTLS_GET_IV_RECV		11
#define KTLS_GET_KEY_RECV		12
#define KTLS_GET_SALT_RECV		13
#define KTLS_GET_IV_SEND		14
#define KTLS_GET_KEY_SEND		15
#define KTLS_GET_SALT_SEND		16
#define KTLS_GET_MTU			17

/* Supported ciphers */
#define KTLS_CIPHER_AES_GCM_128		51

#define KTLS_VERSION_LATEST		0
#define KTLS_VERSION_1_2		1

/* Constants */
#define KTLS_AES_GCM_128_IV_SIZE	((size_t)8)
#define KTLS_AES_GCM_128_KEY_SIZE	((size_t)16)
#define KTLS_AES_GCM_128_SALT_SIZE	((size_t)4)

/* Maximum data size carried in a TLS/DTLS record */
#define KTLS_MAX_PAYLOAD_SIZE		((size_t)1 << 14)

struct sockaddr_ktls {
	__u16   sa_cipher;
	__u16   sa_socket;
	__u16   sa_version;
};

#define IS_TLS(T)			((T)->sk.sk_type == SOCK_STREAM)
#define IS_DTLS(T)			(!IS_TLS(T))
#define MAX(a, b)			((a) > (b) ? (a) : (b))

#define KTLS_RECORD_DATA		0x17

#define KTLS_KEY_SIZE			KTLS_AES_GCM_128_KEY_SIZE
#define KTLS_SALT_SIZE			KTLS_AES_GCM_128_SALT_SIZE
#define KTLS_TAG_SIZE			16
#define KTLS_IV_SIZE			KTLS_AES_GCM_128_IV_SIZE
#define KTLS_NONCE_SIZE			8

#define KTLS_DATA_PAGES			(KTLS_MAX_PAYLOAD_SIZE / PAGE_SIZE)
/* +1 for aad, +1 for tag, +1 for chaining */
#define KTLS_SG_DATA_SIZE		(KTLS_DATA_PAGES + 3)

#define KTLS_AAD_SPACE_SIZE		21
#define KTLS_AAD_SIZE			13

/* TLS
 */
#define KTLS_TLS_HEADER_SIZE		5
#define KTLS_TLS_PREPEND_SIZE		(KTLS_TLS_HEADER_SIZE + KTLS_NONCE_SIZE)
#define KTLS_TLS_OVERHEAD		(KTLS_TLS_PREPEND_SIZE + KTLS_TAG_SIZE)

#define KTLS_TLS_1_2_MAJOR		0x03
#define KTLS_TLS_1_2_MINOR		0x03

/* nonce explicit offset in a record */
#define KTLS_TLS_NONCE_OFFSET		KTLS_TLS_HEADER_SIZE

#define KTLS_PREPEND_SIZE(T)          (IS_TLS(T) ?			\
					(KTLS_TLS_PREPEND_SIZE) :	\
					(KTLS_DTLS_PREPEND_SIZE))

#define KTLS_HEADER_SIZE(T)           (IS_TLS(T) ?			\
					(KTLS_TLS_HEADER_SIZE) :	\
					(KTLS_DTLS_HEADER_SIZE))

#define KTLS_OVERHEAD(T)              (IS_TLS(T) ?		\
					(KTLS_TLS_OVERHEAD) :	\
					(KTLS_DTLS_OVERHEAD))

/* DTLS
 */
#define KTLS_DTLS_HEADER_SIZE		13
#define KTLS_DTLS_PREPEND_SIZE		(KTLS_DTLS_HEADER_SIZE \
						+ KTLS_NONCE_SIZE)
#define KTLS_DTLS_OVERHEAD		(KTLS_DTLS_PREPEND_SIZE \
						+ KTLS_TAG_SIZE)

#define KTLS_DTLS_1_2_MAJOR		0xFE
#define KTLS_DTLS_1_2_MINOR		0xFD

/* we are handling epoch and seq num as one unit */
#define KTLS_DTLS_SEQ_NUM_OFFSET	3
/* nonce explicit offset in a record */
#define KTLS_DTLS_NONCE_OFFSET		KTLS_DTLS_HEADER_SIZE

/* Ensure that bind(2) was called
 */
#define KTLS_SETSOCKOPT_READY(T)	((T)->aead_send && (T)->aead_recv)
#define KTLS_GETSOCKOPT_READY(T)	KTLS_SETSOCKOPT_READY(T)

/* Ensure that we have needed key material
 */
#define KTLS_SEND_READY(T)		((T)->key_send.keylen && \
						(T)->key_send.saltlen && \
						(T)->iv_send && \
						KTLS_GETSOCKOPT_READY(T))
#define KTLS_RECV_READY(T)		((T)->key_recv.keylen && \
						(T)->key_recv.saltlen && \
						(T)->iv_recv && \
						KTLS_GETSOCKOPT_READY(T))

struct tls_key {
	char *key;
	size_t keylen;
	char salt[KTLS_SALT_SIZE];
	size_t saltlen;
};

struct tls_sock {
	/* struct sock must be the very first member */
	struct sock sk;

	/* TCP/UDP socket we are bound to */
	struct socket *socket;

	int rx_stopped;

	/* Context for {set,get}sockopt() */
	unsigned char *iv_send;
	struct tls_key key_send;

	unsigned char *iv_recv;
	struct tls_key key_recv;

	struct crypto_aead *aead_send;
	struct crypto_aead *aead_recv;

	/* Sending context */
	struct scatterlist sg_tx_data[KTLS_SG_DATA_SIZE];
	struct scatterlist sg_tx_data2[ALG_MAX_PAGES + 1];
	char aad_send[KTLS_AAD_SPACE_SIZE];
	char tag_send[KTLS_TAG_SIZE];
	struct page *pages_send;
	int send_offset;
	int send_len;
	int order_npages;
	struct scatterlist sgaad_send[2];
	struct scatterlist sgtag_send[2];
	struct work_struct send_work;

	/* Receive */
	struct scatterlist sgin[ALG_MAX_PAGES + 1];
	char aad_recv[KTLS_AAD_SPACE_SIZE];
	char header_recv[MAX(KTLS_TLS_PREPEND_SIZE, KTLS_DTLS_PREPEND_SIZE)];

	struct strparser strp;
	struct sk_buff_head rx_hold_queue;
	struct work_struct recv_work;
	void (*saved_sk_data_ready)(struct sock *sk);
	void (*saved_sk_write_space)(struct sock *sk);
	size_t recv_len;

	/* our cipher type and its crypto API representation (e.g. "gcm(aes)")
	 */
	unsigned int cipher_type;
	char *cipher_crypto;

	/* TLS/DTLS version for header */
	char version[2];

	/* DTLS window handling */
	struct {
		u64 bits;
		/* The starting point of the sliding window without epoch */
		u64 start;
	} dtls_window;

	int unsent;

	struct tls_record_info *record;
};

struct tls_rx_msg {
	/* strp_rx_msg must be first to match strparser */
	struct strp_rx_msg rxm;
	int decrypted;
};

static inline struct tls_rx_msg *tls_rx_msg(struct sk_buff *skb)
{
	return (struct tls_rx_msg *)((void *)skb->cb +
		offsetof(struct qdisc_skb_cb, data));
}

static inline struct tls_sock *tls_sk(struct sock *sk)
{
	return (struct tls_sock *)sk;
}

static inline void tls_err_abort(struct tls_sock *tsk)
{
	struct sock *sk;

	sk = (struct sock *)tsk;
	xchg(&tsk->rx_stopped, 1);
	xchg(&sk->sk_err, -EBADMSG);
	sk->sk_error_report(sk);
	tsk->saved_sk_data_ready(tsk->socket->sk);
}

static inline void tls_increment_seqno(unsigned char *seq, struct tls_sock *tsk)
{
	int i;

	for (i = 7; i >= 0; i--) {
		++seq[i];
		if (seq[i] != 0)
			break;
	}
	/* Check for overflow. If overflowed, connection must
	 * disconnect.  Raise an error and notify userspace.
	 */
	if (unlikely((IS_TLS(tsk) && i == -1) || (IS_DTLS(tsk) && i <= 1)))
		tls_err_abort(tsk);
}

static inline void tls_make_prepend(struct tls_sock *tsk,
				    char *buf,
				    size_t plaintext_len)
{
	size_t pkt_len;

	pkt_len = plaintext_len + KTLS_IV_SIZE + KTLS_TAG_SIZE;

	/* we cover nonce explicit here as well, so buf should be of
	 * size KTLS_DTLS_HEADER_SIZE + KTLS_DTLS_NONCE_EXPLICIT_SIZE
	 */
	buf[0] = KTLS_RECORD_DATA;
	buf[1] = tsk->version[0];
	buf[2] = tsk->version[1];
	/* we can use IV for nonce explicit according to spec */
	if (IS_TLS(tsk)) {
		buf[3] = pkt_len >> 8;
		buf[4] = pkt_len & 0xFF;
		memcpy(buf + KTLS_TLS_NONCE_OFFSET, tsk->iv_send, KTLS_IV_SIZE);
	} else {
		memcpy(buf + 3, tsk->iv_send, KTLS_IV_SIZE);
		buf[11] = pkt_len >> 8;
		buf[12] = pkt_len & 0xFF;
		memcpy(buf + KTLS_DTLS_NONCE_OFFSET,
		       tsk->iv_send,
		       KTLS_IV_SIZE);
	}
}

int tls_set_offload(struct socket *sock, char __user *src, size_t src_len);
int tls_sendmsg_with_offload(struct tls_sock *tsk, struct msghdr *msg,
			     size_t size);
ssize_t tls_sendpage_with_offload(struct socket *sock, struct page *page,
				  int offset, size_t size, int flags);
#endif
