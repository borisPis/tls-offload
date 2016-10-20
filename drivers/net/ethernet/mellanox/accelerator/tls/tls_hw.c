/*
 * Copyright (c) 2015-2016 Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "tls_hw.h"
#include "mlx_tls_cmds.h"
#include <linux/inetdevice.h>
#include <linux/socket.h>

#include "crypto/af_ktls/af_ktls.h"


/* [BP]: TODO: Fix the I2C for TLS */
#ifndef MLX_TLS_SADB_RDMA

#define TLS_FLUSH_CACHE_ADDR	0x144
#define TLS_FLUSH_CACHE_BIT	0x100
#define SADB_SLOT_SIZE			0x80

static void mlx_tls_flush_cache(struct mlx_tls_dev *dev)
{
	int res;
	u32 dw;

	res = mlx_accel_core_mem_read(dev->accel_device, 4,
				      TLS_FLUSH_CACHE_ADDR, &dw,
				      MLX_ACCEL_ACCESS_TYPE_I2C);
	if (res != 4) {
		pr_warn("TLS cache flush failed on read\n");
		return;
	}

	dw ^= htonl(TLS_FLUSH_CACHE_BIT);
	res = mlx_accel_core_mem_write(dev->accel_device, 4,
				       TLS_FLUSH_CACHE_ADDR, &dw,
				       MLX_ACCEL_ACCESS_TYPE_I2C);
	if (res != 4) {
		pr_warn("TLS cache flush failed on write\n");
		return;
	}
}

static void copy_context_to_hw(void *dst, void *src, unsigned int bytes)
{
	u32 *dst_w = dst, *src_w = src;
	unsigned int i, words = bytes / 4;

	WARN_ON(bytes & 3);
	for (i = 0; i < words; i++)
		dst_w[i] = htonl(src_w[i]);
}

int mlx_ktls_hw_start_cmd(struct mlx_tls_dev *dev, struct sock *sk,
				  struct tls_offload_context *data,
				  struct ktls_keys *keys) {
	return 0;
}

void mlx_ktls_hw_stop_cmd(struct net_device *netdev, struct sock *sk)
{
}

#else /* MLX_TLS_SADB_RDMA */

static void mlx_ktls_del_work(struct work_struct *w);
static DEFINE_SPINLOCK(ktls_del_lock);
static DECLARE_COMPLETION(setup_flow_completion);
static DECLARE_WORK(ktls_del_work, mlx_ktls_del_work);
static LIST_HEAD(ktls_del_list);


#define UPDATE_CTX_FIELD_SIZE(field, value, size) memcpy(((void*)(field))+sizeof(field)-(size), (value), (size))
#define UPDATE_CTX_FIELD(field, value) UPDATE_CTX_FIELD_SIZE(field, value, sizeof(*value))

int mlx_ktls_hw_start_cmd(struct mlx_tls_dev *dev, struct sock *sk,
			  struct mlx_tls_offload_context *context,
			  struct ktls_keys *keys) {
	struct mlx_accel_core_dma_buf *buf;
	struct setup_stream_cmd *cmd;
	struct inet_sock *inet = inet_sk(sk);
	__be32 expectedSN = htonl(context->context.expectedSN);
	int size = sizeof(*buf) + sizeof(*cmd);

	buf = kzalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	buf->data = buf + 1;
	buf->data_size = sizeof(*cmd);

	cmd = (struct setup_stream_cmd *) buf->data;
	cmd->cmd = CMD_SETUP_STREAM;
	if (sk->sk_family != PF_INET6) {
		UPDATE_CTX_FIELD(cmd->tls.tcp.ip_sa,&inet->inet_rcv_saddr);
		UPDATE_CTX_FIELD(cmd->tls.tcp.ip_da,&inet->inet_daddr);
		cmd->tls.tcp.flags |= TLS_TCP_IPV4;
	} else {
		/* [BP]: TODO support ipv6 */
		memcpy(cmd->tls.tcp.ip_sa,
				inet->pinet6->saddr.in6_u.u6_addr8, 16);
		memcpy(cmd->tls.tcp.ip_da,
				inet->pinet6->daddr_cache->in6_u.u6_addr8, 16);
		pr_err("IPv6 isn't supported yet\n");
		return -EINVAL;
	}
	cmd->tls.tcp.flags |= TLS_TCP_IP_PROTO;
	cmd->tls.tcp.flags |= TLS_TCP_VALID;
	cmd->tls.tcp.flags |= TLS_TCP_INIT;
	cmd->tls.tcp.src_port = inet->inet_sport;
	cmd->tls.tcp.dst_port = inet->inet_dport;
	cmd->tls.tcp.tcp_sn = expectedSN;

	/* cmd->tls.rcd.rcd_tcp_sn = expectedSN; */
	/* cmd->tls.rcd.rcd_tcp_sn_nxt = expectedSN; */
	cmd->tls.rcd.enc_auth_mode |= TLS_RCD_AUTH_AES_GCM128;
	cmd->tls.rcd.enc_auth_mode |= TLS_RCD_ENC_AES_GCM128;
	cmd->tls.rcd.rcd_type_ver |= TLS_RCD_VER_1_2;

	memcpy(&cmd->tls.rcd.rcd_implicit_iv,
	       &keys->tx.salt, KTLS_AES_GCM_128_SALT_SIZE);
	UPDATE_CTX_FIELD(cmd->tls.rcd.rcd_sn, &keys->tx.iv);
	UPDATE_CTX_FIELD(cmd->tls.crypto.enc_key, &keys->tx.key);

	reinit_completion(&setup_flow_completion);
	mlx_accel_core_sendmsg(dev->conn, buf);
	wait_for_completion_killable(&setup_flow_completion);

	return 0;
}

void mlx_ktls_hw_stop_cmd(struct net_device *netdev, struct sock *sk)
{
	unsigned long flags;
	struct mlx_tls_offload_context *context = sk->sk_tls_offload;

	pr_info("mlx_ktls_stop\n");

	spin_lock_irqsave(&ktls_del_lock, flags);
	list_add_tail(&context->ktls_del_list, &ktls_del_list);
	context->netdev = netdev;
	schedule_work(&ktls_del_work);
	spin_unlock_irqrestore(&ktls_del_lock, flags);
}

static void mlx_ktls_del_work(struct work_struct *w)
{
	unsigned long flags;
	struct mlx_tls_offload_context *context;
	struct mlx_tls_dev *dev;

	while (true) {
		spin_lock_irqsave(&ktls_del_lock, flags);
		context = list_first_entry_or_null(&ktls_del_list,
				struct mlx_tls_offload_context, ktls_del_list);
		if (!context) {
			spin_unlock_irqrestore(&ktls_del_lock, flags);
			return;
		}

		list_del(&context->ktls_del_list);
		spin_unlock_irqrestore(&ktls_del_lock, flags);

		dev = mlx_tls_find_dev_by_netdev(context->netdev);

		mutex_lock(&dev->id_mutex);
		idr_remove(&dev->swid_idr, context->swid);
		mutex_unlock(&dev->id_mutex);

		kfree(context);
		module_put(THIS_MODULE);
	}
}

void mlx_tls_hw_qp_recv_cb(void *cb_arg,
		struct mlx_accel_core_dma_buf *buf)
{
	struct generic_event *ev = (struct generic_event *) buf->data;

	switch (ev->opcode) {
	case htonl(EVENT_SETUP_STREAM_RESPONSE):
		complete(&setup_flow_completion);
		break;
	default:
		pr_warn("mlx_tls_hw_qp_recv_cb: unexpected event opcode %u\n", ntohl(ev->opcode));
	}
}

#endif /* MLX_TLS_SADB_RDMA */
