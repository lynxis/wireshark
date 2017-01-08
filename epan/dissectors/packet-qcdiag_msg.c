/* packet-qcdiag_msg.c
 * Routines for Qualcomm DIAG MSG packet handling
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

static int proto_qcdiag_msg = -1;

static int hf_qcdiag_msg_ts_type = -1;
static int hf_qcdiag_msg_num_args = -1;
static int hf_qcdiag_msg_drop_cnt = -1;
static int hf_qcdiag_msg_line_nr = -1;
static int hf_qcdiag_msg_subsys_id = -1;
static int hf_qcdiag_msg_subsys_mask = -1;
static int hf_qcdiag_msg_fmt_str = -1;
static int hf_qcdiag_msg_formatted_str = -1;
static int hf_qcdiag_msg_file_name = -1;
static int hf_qcdiag_msg_argument = -1;

static gint ett_qcdiag_msg = -1;

#define MAX_ARGS	16

static void
sanitize_fmtstr(guint8 *fmt)
{
	guint8 *cur;

	/* replace all CR/LF to avoid having multi-line COL_INFO */
	for (cur = fmt; cur < fmt + strlen(fmt); cur++) {
		if (*cur == '\n' || *cur == '\r')
			*cur = ';';
	}

	/* Replace all '%s' with '%p', as this simply doesn't work in a
	 * remte-printf situation. We cannot access the address on the
	 * target device.  People putting format strings into QCDIAG MSG
	 * should know that, but pparently some times try anyway :/ */
	for (cur = fmt; cur && (cur < fmt + strlen(fmt)); cur = strstr(fmt, "%s")) {
		cur[1] = 'p';
	}
	/* FIXME: catch cases like '% s' or '%-20s' */
}

static int
dissect_qcdiag_msg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
	proto_item *ti, *gi;
	proto_tree *diag_msg_tree;
	gint offset = 1; /* command already dissected by proto-qcdiag.c */
	guint num_args, line_nr, subsys_id, subsys_mask, i, fmtstr_offset;
	const guint8 *file_name;
	guint8 *fmtstr;
	gchar *str = NULL;
	guint args[MAX_ARGS];

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "QCDIAG-MSG");

	ti = proto_tree_add_item(tree, proto_qcdiag_msg, tvb, 0, -1, ENC_NA);
	diag_msg_tree = proto_item_add_subtree(ti, ett_qcdiag_msg);

	proto_tree_add_item(diag_msg_tree, hf_qcdiag_msg_ts_type, tvb, offset++, 1, ENC_NA);
	proto_tree_add_item_ret_uint(diag_msg_tree, hf_qcdiag_msg_num_args, tvb, offset++, 1, ENC_NA, &num_args);
	proto_tree_add_item(diag_msg_tree, hf_qcdiag_msg_drop_cnt, tvb, offset++, 1, ENC_NA);
	/* timestamp */
	offset += 8;

	proto_tree_add_item_ret_uint(diag_msg_tree, hf_qcdiag_msg_line_nr, tvb, offset, 2, ENC_LITTLE_ENDIAN, &line_nr);
	offset += 2;

	proto_tree_add_item_ret_uint(diag_msg_tree, hf_qcdiag_msg_subsys_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &subsys_id);
	offset += 2;

	proto_tree_add_item_ret_uint(diag_msg_tree, hf_qcdiag_msg_subsys_mask, tvb, offset, 4, ENC_LITTLE_ENDIAN, &subsys_mask);
	offset += 4;

	/* Append all arguments */
	for (i = 0; i < num_args; i++) {
		if (i < MAX_ARGS)
			proto_tree_add_item_ret_uint(diag_msg_tree, hf_qcdiag_msg_argument, tvb, offset, 4, ENC_LITTLE_ENDIAN, &args[i]);
		else
			proto_tree_add_item(diag_msg_tree, hf_qcdiag_msg_argument, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
	}

	/* we cannot use _ret_string() here, as we need an editable
	 * (non-const) version of the string to sanitize it */
	proto_tree_add_item(diag_msg_tree, hf_qcdiag_msg_fmt_str, tvb, offset, -1, ENC_ASCII|ENC_NA);
	fmtstr = tvb_get_stringzpad(wmem_packet_scope(), tvb, offset, tvb_strsize(tvb, offset), ENC_ASCII);
	fmtstr_offset = offset;
	offset += tvb_strsize(tvb, offset);
	sanitize_fmtstr(fmtstr);

	proto_tree_add_item_ret_string(diag_msg_tree, hf_qcdiag_msg_file_name, tvb, offset, -1, ENC_ASCII, wmem_packet_scope(), &file_name);
	offset += tvb_strsize(tvb, offset);

	col_append_fstr(pinfo->cinfo, COL_INFO, "%s:%u ", file_name, line_nr);
	switch (num_args) {
	case 0:
		str = wmem_strdup_printf(wmem_packet_scope(), "%s", fmtstr);
		break;
	case 1:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0]);
		break;
	case 2:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1]);
		break;
	case 3:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2]);
		break;
	case 4:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3]);
		break;
	case 5:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4]);
		break;
	case 6:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5]);
		break;
	case 7:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6]);
		break;
	case 8:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
		break;
	case 9:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8]);
		break;
	case 10:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8], args[9]);
		break;
	case 11:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8], args[9], args[10]);
		break;
	case 12:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8], args[9], args[10], args[11]);
		break;
	case 13:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8], args[9], args[10], args[11], args[12]);
		break;
	case 14:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8], args[9], args[10], args[11], args[12], args[13]);
		break;
	case 15:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8], args[9], args[10], args[11], args[12], args[13], args[14]);
		break;
	case 16:
		str = wmem_strdup_printf(wmem_packet_scope(), fmtstr, args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7],
				args[8], args[9], args[10], args[11], args[12], args[13], args[14], args[15]);
		break;
	}

	proto_item_append_text(ti, ", Subsys: %u, Mask: 0x%04x, %s:%u",
				subsys_id, subsys_mask, file_name, line_nr);

	if (str) {
		col_append_str((pinfo)->cinfo, COL_INFO, str);
		gi = proto_tree_add_string(diag_msg_tree, hf_qcdiag_msg_formatted_str, tvb, fmtstr_offset, strlen(fmtstr), str);
		PROTO_ITEM_SET_GENERATED(gi);
		proto_item_append_text(ti, " %s", str);
	}

	return tvb_captured_length(tvb);
}

void
proto_register_qcdiag_msg(void)
{
	static hf_register_info hf[] = {
		{ &hf_qcdiag_msg_ts_type, { "Timestamp Type", "qcdiag_msg.ts_type",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_num_args, { "Number of Arguments", "qcdiag_msg.num_args",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_drop_cnt, { "Dropped message count", "qcdiag_msg.num_drop_cnt",
		  FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_line_nr, { "Line Number", "qcdiag_msg.line_nr",
		  FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_subsys_id, { "Subsystem ID", "qcdiag_msg.subsys_id",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_subsys_mask, { "Subsystem Mask", "qcdiag_msg.subsys_mask",
		  FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_fmt_str, { "Format String", "qcdiag_msg.fmt_str",
		  FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_formatted_str, { "Formatted String", "qcdiag_msg.formatted_str",
		  FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_file_name, { "File Name", "qcdiag_msg.fmt_str",
		  FT_STRINGZ, BASE_NONE, NULL, 0, NULL, HFILL } },
		{ &hf_qcdiag_msg_argument, { "Argument", "qcdiag_msg.argument",
		  FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
	};
	static gint *ett[] = {
		&ett_qcdiag_msg
	};

	proto_qcdiag_msg = proto_register_protocol("Qualcomm DIAG Msg", "QCDIAG MSG", "qcdiag_msg");
	proto_register_field_array(proto_qcdiag_msg, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_qcdiag_msg(void)
{
	dissector_handle_t qcdiag_msg_handle;

	qcdiag_msg_handle = create_dissector_handle(dissect_qcdiag_msg, proto_qcdiag_msg);
	dissector_add_uint("qcdiag.cmd", DIAG_EXT_MSG_F, qcdiag_msg_handle);
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
