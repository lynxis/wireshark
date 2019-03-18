/* packet-qcdiag_log.c
 * Routines for Qualcomm DIAG LOG packet handling
 *
 * (C) 2016-2017 by Harald Welte <laforge@gnumonks.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-qcdiag.h"

static dissector_table_t qcdiag_log_code_dissector_table;

static int proto_qcdiag_log = -1;

static int hf_qcdiag_log_len = -1;
static int hf_qcdiag_log_code = -1;

static int hf_rr_chan_type = -1;
static int hf_rr_downlink = -1;
static int hf_rr_msg_type = -1;
static int hf_msg_length = -1;

static int hf_mac_chan_type = -1;
static int hf_mac_msg_type = -1;

static int hf_nas_msg_length = -1;
static int hf_nas_direction = -1;

static int hf_rrc_chan_type = -1;
static int hf_rrc_rb_id = -1;
static int hf_rrc_length = -1;

static gint ett_qcdiag_log = -1;

enum {
	SUB_DATA = 0,
	SUB_UM_CCCH,
	SUB_UM_DTAP,
	SUB_UM_SACCH,
	SUB_UM_RLC_MAC_UL,
	SUB_UM_RLC_MAC_DL,
	SUB_CBCH,
	SUB_SIM,
	/* UMTS */
	SUB_RRC_DL_CCCH,
	SUB_RRC_UL_CCCH,
	SUB_RRC_DL_DCCH,
	SUB_RRC_UL_DCCH,
	SUB_RRC_BCCH_BCH,
	SUB_RRC_BCCH_FACH,
	SUB_RRC_PCCH,

	SUB_MAX
};

static dissector_handle_t sub_handles[SUB_MAX];

enum diag_gsm_rr_chan_type {
	DIAG_GSM_L2_CHAN_TYPE_DCCH	= 0,
	DIAG_GSM_L2_CHAN_TYPE_BCCH	= 1,
	DIAG_GSM_L2_CHAN_TYPE_RACH	= 2,
	DIAG_GSM_L2_CHAN_TYPE_CCCH	= 3,
	DIAG_GSM_L2_CHAN_TYPE_SACCH	= 4,
	DIAG_GSM_L2_CHAN_TYPE_SDCCH	= 5,
	DIAG_GSM_L2_CHAN_TYPE_FACCH_F	= 6,
	DIAG_GSM_L2_CHAN_TYPE_FACCH_H	= 7,
};

static const value_string rr_chan_types[] = {
	{ DIAG_GSM_L2_CHAN_TYPE_DCCH,	"DCCH" },
	{ DIAG_GSM_L2_CHAN_TYPE_BCCH,	"BCCH" },
	{ DIAG_GSM_L2_CHAN_TYPE_RACH,	"RACH" },
	{ DIAG_GSM_L2_CHAN_TYPE_CCCH,	"CCCH" },
	{ DIAG_GSM_L2_CHAN_TYPE_SACCH,	"SACCH" },
	{ DIAG_GSM_L2_CHAN_TYPE_SDCCH,	"SDCCH" },
	{ DIAG_GSM_L2_CHAN_TYPE_FACCH_F,"FACCH/F" },
	{ DIAG_GSM_L2_CHAN_TYPE_FACCH_H,"FACCH/H" },
	{ 0, NULL }
};

static const true_false_string rr_direction_vals = {
	"Downlink",
	"Uplink",
};

static const true_false_string nas_direction_vals = {
	"Uplink",
	"Downlink",
};

enum gprs_mac_chan_type {
	PRACH_11BIT_CHANNEL	= 0x01,
	PRACH_8BIT_CHANNEL	= 0x02,
	PACCH_RRBP_CHANNEL	= 0x03,
	UL_PACCH_CHANNEL	= 0x04,
	PCCCH_CHANNEL		= 0x81,
	PBCCH_CHANNEL		= 0x82,
	DL_PACCH_CHANNEL	= 0x83,
};

static const value_string mac_chan_types[] = {
	{ PRACH_11BIT_CHANNEL,	"PRACH(11bit)" },
	{ PRACH_8BIT_CHANNEL,	"PRACH(8bit)" },
	{ PACCH_RRBP_CHANNEL,	"PACCH(RRBP)" },
	{ UL_PACCH_CHANNEL,	"PACCH(Uplink)" },
	{ PCCCH_CHANNEL,	"PCCCH" },
	{ PBCCH_CHANNEL,	"PBCCH" },
	{ DL_PACCH_CHANNEL,	"PACCH(Downlink)" },
	{ 0, NULL }
};

enum diag_umts_rrc_chtype {
	DIAG_UMTS_RRC_CHT_UL_CCCH	= 0,
	DIAG_UMTS_RRC_CHT_UL_DCCH	= 1,
	DIAG_UMTS_RRC_CHT_DL_CCCH	= 2,
	DIAG_UMTS_RRC_CHT_DL_DCCH	= 3,
	DIAG_UMTS_RRC_CHT_DL_BCCH_BCH	= 4,
	DIAG_UMTS_RRC_CHT_DL_BCCH_FACH	= 5,
	DIAG_UMTS_RRC_CHT_DL_PCCH	= 6,
};

static const value_string rrc_chan_types[] = {
	{ DIAG_UMTS_RRC_CHT_UL_CCCH,	"CCCH(Uplink)" },
	{ DIAG_UMTS_RRC_CHT_UL_DCCH,	"DCCH(Uplink)" },
	{ DIAG_UMTS_RRC_CHT_DL_CCCH,	"CCCH(Downlink)" },
	{ DIAG_UMTS_RRC_CHT_DL_DCCH,	"DCCH(Downlink)" },
	{ DIAG_UMTS_RRC_CHT_DL_BCCH_BCH,"BCCH/BCH" },
	{ DIAG_UMTS_RRC_CHT_DL_BCCH_FACH, "BCCH/FACH" },
	{ DIAG_UMTS_RRC_CHT_DL_PCCH,	"PCCH" },
	{ 0, NULL }
};

static int
dissect_qcdiag_log_rrc(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
	tvbuff_t *payload_tvb;
	guint chan_type, rrc_length;
	gint sub_handle;

	proto_tree_add_item_ret_uint(log_tree, hf_rrc_chan_type, tvb, offset++, 1, ENC_NA, &chan_type);

	proto_tree_add_item(log_tree, hf_rrc_rb_id, tvb, offset++, 1, ENC_NA);

	proto_tree_add_item_ret_uint(log_tree, hf_rrc_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &rrc_length);
	offset += 2;

	/* Data: Raw RRC Message */
	payload_tvb = tvb_new_subset_length(tvb, offset, rrc_length);

	switch (chan_type) {
	case DIAG_UMTS_RRC_CHT_UL_CCCH:
		sub_handle = SUB_RRC_UL_CCCH;
		break;
	case DIAG_UMTS_RRC_CHT_DL_DCCH:
		sub_handle = SUB_RRC_DL_DCCH;
		break;
	case DIAG_UMTS_RRC_CHT_UL_DCCH:
		sub_handle = SUB_RRC_UL_DCCH;
		break;
	case DIAG_UMTS_RRC_CHT_DL_CCCH:
		sub_handle = SUB_RRC_DL_CCCH;
		break;
	case DIAG_UMTS_RRC_CHT_DL_BCCH_BCH:
		sub_handle = SUB_RRC_BCCH_BCH;
		break;
	case DIAG_UMTS_RRC_CHT_DL_BCCH_FACH:
		sub_handle = SUB_RRC_BCCH_FACH;
		break;
	case DIAG_UMTS_RRC_CHT_DL_PCCH:
		sub_handle = SUB_RRC_PCCH;
		break;
	default:
		sub_handle = SUB_DATA;
		break;
	};

	if (sub_handles[sub_handle])
		call_dissector(sub_handles[sub_handle], payload_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int
dissect_qcdiag_log_rr(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
	tvbuff_t *payload_tvb;
	guint chan_type, rr_length;
	gint sub_handle;

	/* Byte 1 */
	proto_tree_add_item_ret_uint(log_tree, hf_rr_chan_type, tvb, offset, 1, ENC_NA, &chan_type);
	proto_tree_add_item(log_tree, hf_rr_downlink, tvb, offset++, 1, ENC_NA);

	/* Byte 2 */
	proto_tree_add_item(log_tree, hf_rr_msg_type, tvb, offset++, 1, ENC_NA);

	/* Byte 3 */
	proto_tree_add_item_ret_uint(log_tree, hf_msg_length, tvb, offset++, 1, ENC_NA, &rr_length);

	/* Data: Raw RR Message */
	payload_tvb = tvb_new_subset_length(tvb, offset, rr_length);

	switch (chan_type) {
	case DIAG_GSM_L2_CHAN_TYPE_BCCH:
	case DIAG_GSM_L2_CHAN_TYPE_CCCH:
		sub_handle = SUB_UM_CCCH;
		break;
	case DIAG_GSM_L2_CHAN_TYPE_SACCH:
		sub_handle = SUB_UM_SACCH;
		break;
	case DIAG_GSM_L2_CHAN_TYPE_SDCCH:
	case DIAG_GSM_L2_CHAN_TYPE_DCCH:
	case DIAG_GSM_L2_CHAN_TYPE_FACCH_F:
	case DIAG_GSM_L2_CHAN_TYPE_FACCH_H:
		sub_handle = SUB_UM_DTAP;
		break;
	default:
		sub_handle = SUB_DATA;
		break;
	}

	if (sub_handles[sub_handle])
		call_dissector(sub_handles[sub_handle], payload_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int
dissect_qcdiag_log_gmac(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
	tvbuff_t *payload_tvb;
	guint chan_type, mac_length;
	gint sub_handle;

	/* Byte 1 */
	proto_tree_add_item_ret_uint(log_tree, hf_mac_chan_type, tvb, offset++, 1, ENC_NA, &chan_type);

	/* Byte 2 */
	proto_tree_add_item(log_tree, hf_mac_msg_type, tvb, offset++, 1, ENC_NA);

	/* Byte 3 */
	proto_tree_add_item_ret_uint(log_tree, hf_msg_length, tvb, offset++, 1, ENC_NA, &mac_length);

	/* Data: Raw RR Message */
	payload_tvb = tvb_new_subset_length(tvb, offset, mac_length);

	switch (chan_type) {
	case PRACH_11BIT_CHANNEL:
	case PRACH_8BIT_CHANNEL:
	case UL_PACCH_CHANNEL:
		sub_handle = SUB_UM_RLC_MAC_UL;
		break;
	case PCCCH_CHANNEL:
	case PBCCH_CHANNEL:
	case DL_PACCH_CHANNEL:
		sub_handle = SUB_UM_RLC_MAC_DL;
		break;
	case PACCH_RRBP_CHANNEL:
	default:
		sub_handle = SUB_DATA;
	}

	if (sub_handles[sub_handle])
		call_dissector(sub_handles[sub_handle], payload_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int
dissect_qcdiag_log_nas(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
	tvbuff_t *payload_tvb;
	guint length;

	/* Byte 1: Direction */
	proto_tree_add_item(log_tree, hf_nas_direction, tvb, offset++, 1, ENC_NA);

	/* Byte 2-5: Length */
	proto_tree_add_item_ret_uint(log_tree, hf_nas_msg_length, tvb, offset, 4, ENC_LITTLE_ENDIAN, &length);
	offset += 4;

	/* Byte 6...: NAS Message */
	payload_tvb = tvb_new_subset_length(tvb, offset, length);

	if (sub_handles[SUB_UM_DTAP])
		call_dissector(sub_handles[SUB_UM_DTAP], payload_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}

static int
dissect_qcdiag_log_uim(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *log_tree, proto_tree *tree)
{
	tvbuff_t *payload_tvb;
	guint uim_length;

	/* Byte 1 */
	proto_tree_add_item_ret_uint(log_tree, hf_msg_length, tvb, offset++, 1, ENC_NA, &uim_length);

	/* Data: Raw UIM Message */
	payload_tvb = tvb_new_subset_length(tvb, offset, uim_length);

	if (sub_handles[SUB_SIM])
		call_dissector(sub_handles[SUB_SIM], payload_tvb, pinfo, tree);

	return tvb_captured_length(tvb);
}


static int
dissect_qcdiag_log(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
	proto_item *ti;
	proto_tree *diag_log_tree;
	tvbuff_t *payload_tvb;
	gint offset = 0;
	guint len, code;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "QCDIAG-LOG");

	ti = proto_tree_add_item(tree, proto_qcdiag_log, tvb, 0, -1, ENC_NA);
	diag_log_tree = proto_item_add_subtree(ti, ett_qcdiag_log);

	/* 4 bytes common header */
	offset += 4;

	proto_tree_add_item_ret_uint(diag_log_tree, hf_qcdiag_log_len, tvb, offset, 2, ENC_LITTLE_ENDIAN, &len);
	offset += 2;

	proto_tree_add_item_ret_uint(diag_log_tree, hf_qcdiag_log_code, tvb, offset, 2, ENC_LITTLE_ENDIAN, &code);
	offset += 2;

	/* 8 bytes timestamp */
	offset += 8;

	switch (code) {
	case 0x1098:	/* UIM Application Protocol Data Unit */
		return dissect_qcdiag_log_uim(tvb, offset, pinfo, diag_log_tree, tree);
	case 0x512f:	/* GSM RR signaling message */
		return dissect_qcdiag_log_rr(tvb, offset, pinfo, diag_log_tree, tree);
	case 0x412f:	/* 3G RRC */
		return dissect_qcdiag_log_rrc(tvb, offset, pinfo, diag_log_tree, tree);
	case 0x5202:	/* LOG_GPRS_RLC_UL_STATS_C */
		break;
	case 0x520e:	/* LOG_GPRS_RLC_DL_RELEASE_IND_C */
		break;
	case 0x5226:	/* GPRS MAC signalling message */
		return dissect_qcdiag_log_gmac(tvb, offset, pinfo, diag_log_tree, tree);
	case 0x5230:	/* GPRS GMM */
		break;
	case 0x713a:
		return dissect_qcdiag_log_nas(tvb, offset, pinfo, diag_log_tree, tree);
		break;
	case 0xb0c0:
	case 0xb0e0:
	case 0xb0e1:
	case 0xb0e2:
	case 0xb0e3:
	case 0xb0ea:
	case 0xb0eb:
	case 0xb0ec:
	case 0xb0ed:
		break;
	default:
		payload_tvb = tvb_new_subset_length(tvb, offset, len);
		dissector_try_uint(qcdiag_log_code_dissector_table, code, payload_tvb, pinfo, diag_log_tree);
		break;
	}

	return tvb_captured_length(tvb);
}

void
proto_register_qcdiag_log(void)
{
	static hf_register_info hf[] = {
		{ &hf_qcdiag_log_len, { "Log Message Length", "qcdiag_log.length",
		  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_log_code, { "Log Code", "qcdiag_log.code",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_rr_downlink, { "Direction", "qcdiag_log.downlink",
		  FT_BOOLEAN, 8, TFS(&rr_direction_vals), 0x80, NULL, HFILL } },
		{ &hf_msg_length, { "Message Length", "qcdiag_log.msg_len",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		/* RR */
		{ &hf_rr_chan_type, { "RR Channel Type", "qcdiag_log.rr.chan_type",
		  FT_UINT8, BASE_HEX, VALS(rr_chan_types), 0x7f, NULL, HFILL } },
		{ &hf_rr_msg_type, { "RR Message Type", "qcdiag_log.rr.msg_type",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		/* GPRS MAC */
		{ &hf_mac_chan_type, { "GPRS MAC Channel Type", "qcdiag_log.gmac.chan_type",
		  FT_UINT8, BASE_HEX, VALS(mac_chan_types), 0, NULL, HFILL } },
		{ &hf_mac_msg_type, { "GPRS MAC Message Type", "qcdiag_log.gmac.msg_type",
		  FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
		/* NAS */
		{ &hf_nas_msg_length, { "NAS Message Length", "qcdiag_log.nas.msg_len",
		  FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_nas_direction, { "Direction", "qcdiag_log.nas.direction",
		  FT_BOOLEAN, 8, TFS(&nas_direction_vals), 0x01, NULL, HFILL } },
		/* RRC */
		{ &hf_rrc_chan_type, { "RRC Channel Type", "qcdiag_log.rrc.chan_type",
		  FT_UINT8, BASE_DEC, VALS(rrc_chan_types), 0, NULL, HFILL } },
		{ &hf_rrc_rb_id, {"RRC RB ID", "qcdiag_log.rrc.rb_id",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_rrc_length, {"RRC Message Length", "qcdiag_log.rrc.msg_len",
		  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
	};
	static gint *ett[] = {
		&ett_qcdiag_log
	};

	proto_qcdiag_log = proto_register_protocol("Qualcomm DIAG Log", "QCDIAG LOG", "qcdiag_log");
	proto_register_field_array(proto_qcdiag_log, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	qcdiag_log_code_dissector_table = register_dissector_table("qcdiag_log.code",
					"QCDIAG LOG code", proto_qcdiag_log, FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_qcdiag_log(void)
{
	dissector_handle_t qcdiag_log_handle;

	qcdiag_log_handle = create_dissector_handle(dissect_qcdiag_log, proto_qcdiag_log);
	dissector_add_uint("qcdiag.cmd", DIAG_LOG_F, qcdiag_log_handle);

	sub_handles[SUB_DATA] = find_dissector("data");
	sub_handles[SUB_UM_CCCH] = find_dissector_add_dependency("gsm_a_ccch", proto_qcdiag_log);
	sub_handles[SUB_UM_DTAP] = find_dissector_add_dependency("gsm_a_dtap", proto_qcdiag_log);
	sub_handles[SUB_UM_SACCH] = find_dissector_add_dependency("gsm_a_sacch", proto_qcdiag_log);
	sub_handles[SUB_UM_RLC_MAC_UL] = find_dissector_add_dependency("gsm_rlcmac_ul", proto_qcdiag_log);
	sub_handles[SUB_UM_RLC_MAC_DL] = find_dissector_add_dependency("gsm_rlcmac_dl", proto_qcdiag_log);
	sub_handles[SUB_RRC_DL_CCCH] = find_dissector_add_dependency("rrc.dl.ccch", proto_qcdiag_log);
	sub_handles[SUB_RRC_UL_CCCH] = find_dissector_add_dependency("rrc.ul.ccch", proto_qcdiag_log);
	sub_handles[SUB_RRC_DL_DCCH] = find_dissector_add_dependency("rrc.dl.dcch", proto_qcdiag_log);
	sub_handles[SUB_RRC_UL_DCCH] = find_dissector_add_dependency("rrc.ul.dcch", proto_qcdiag_log);
	sub_handles[SUB_RRC_BCCH_BCH] = find_dissector_add_dependency("rrc.bcch.bch", proto_qcdiag_log);
	sub_handles[SUB_RRC_BCCH_FACH] = find_dissector_add_dependency("rrc.bcch.fach", proto_qcdiag_log);
	sub_handles[SUB_RRC_PCCH] = find_dissector_add_dependency("rrc.pcch", proto_qcdiag_log);
	sub_handles[SUB_SIM] = find_dissector_add_dependency("gsm_sim", proto_qcdiag_log);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
