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

#ifndef MLX_TLS_CMDS_H
#define MLX_TLS_CMDS_H

#define MLX_TLS_SADB_RDMA

enum fpga_cmds {
	CMD_SETUP_STREAM		= 1,
	CMD_TEARDOWN_STREAM		= 2,
};

enum fpga_response {
	EVENT_SETUP_STREAM_RESPONSE	= 0x81,
};

#define TLS_TCP_INIT       BIT(3) // 1 - Initialized
#define TLS_TCP_VALID      BIT(2) // 1 - Valid
#define TLS_TCP_IPV4       BIT(1) // 0 - IPv6; 1 - IPv4
#define TLS_TCP_IP_PROTO   BIT(0) // 0 - UDP; 1 - TCP

struct tls_cntx_tcp {
	u8 ip_sa[16]                ;
	u8 ip_da[16]                ;
	__be16 dst_port             ;
	__be16 src_port             ;
	__be32 tcp_sn               ;
	u8 flags		    ;
	u8 reserved[64-16*2-2*2-4-1];
} __packed;

#define TLS_RCD_ENC_AES_GCM128	(0)
#define TLS_RCD_ENC_AES_GCM256	(1 << 4)
#define TLS_RCD_AUTH_AES_GCM128	 (0)
#define TLS_RCD_AUTH_AES_GCM256	 (1)

#define TLS_RCD_VER_1_2		 (3)

struct tls_cntx_record {
	//rcd_residue		    ;
	u8 rcd_residue[32]	    ;
	__be32 rcd_implicit_iv      ;
	u8 rcd_sn[8]                ;
	__be32 rcd_tcp_sn           ;
	__be16 rcd_tcp_sn_nxt       ;
	//crypto_type               ;
	//mac_type                  ;
	u8 enc_auth_mode	    ;
	//rcd_type                  ;
	//rcd_ver                   ;
	u8 rcd_type_ver		    ;
	//rcd_hdr_position          ;
	//rcd_bypass                ;
	//rcd_sync                  ;
	//chng_cipherspec_det       ;
	u8 flags		    ;
	u8 reserved[64-32-4-8-4-2-1*3];
} __packed;

struct tls_cntx_crypto {
	u8 enc_key[32]		    ;
	u8 enc_state[16]	    ;
	u8 reserved[64-32-16]	    ;
} __packed;

struct tls_cntx_auth {
	u8 auth_state[16]	    ;
	u8 reserved[64-16]	    ;
} __packed;

struct tls_cntx {
	struct tls_cntx_tcp	tcp;
	struct tls_cntx_record	rcd;
	struct tls_cntx_crypto	crypto;
	struct tls_cntx_auth	auth;
} __packed;

struct setup_stream_cmd {
	u8 cmd;
	struct tls_cntx tls;
} __packed;

struct teardown_stream_cmd {
	__be32 cmd;
	__be32 stream_id;
};

struct generic_event {
	__be32 opcode;
	__be32 stream_id;
};

struct data_event {
/* [SR] TODO: Consider just including "generic event" here instead of
 * explicitly listing the same content again.
 */
	__be32 opcode;
	__be32 stream_id;
	__be32 buf_id;
	__be32 len;
	__be32 op_type;
	__be32 op_data;
	char data[];
};

struct event_fast_path_data {
	__be32 opcode;
	__be32 stream_id;
	char data[];
};

struct setup_stream_response {
	__be32 opcode;
	__be32 stream_id;
};

struct process_tx_data_response {
	__be32 opcode;
	__be32 stream_id;
	struct {
		__be32 buf_id;
		__be32 len;
	} data[];
};

#endif /* MLX_TLS_CMDS_H */
