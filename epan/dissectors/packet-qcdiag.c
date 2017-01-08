/* packet-qcdiag.c
 * Routines for Qualcomm DIAG packet handling
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
#include "packet-gsmtap.h"
#include "packet-qcdiag.h"

static dissector_table_t qcdiag_dissector_table;
static dissector_table_t qcdiag_subsys_dissector_table;

static int proto_qcdiag = -1;

static int hf_qcdiag_cmd = -1;
static int hf_qcdiag_subsys_id = -1;
static int hf_qcdiag_subsys_cmd_code = -1;

static gint ett_qcdiag = -1;

static const value_string qcdiag_cmds[] = {
	{ DIAG_VERNO_F,			"Version Number" },
	{ DIAG_ESN_F,			"MS ESN" },
	{ DIAG_PEEKB_F,			"Peek Byte" },
	{ DIAG_PEEKW_F,			"Peek Word" },
	{ DIAG_PEEKD_F,			"Peek DWord" },
	{ DIAG_POKEB_F,			"Poek Byte" },
	{ DIAG_POKEW_F,			"Poke Word" },
	{ DIAG_POKED_F,			"Poke DWord" },
	{ DIAG_OUTP_F,			"Byte output" },
	{ DIAG_OUTPW_F,			"Word output" },
	{ DIAG_INP_F,			"Byte input" },
	{ DIAG_INPW_F,			"Word input" },
	{ DIAG_STATUS_F,		"Status" },
	{ DIAG_LOGMASK_F,		"Set Logging Mask" },
	{ DIAG_LOG_F,			"Log Packet" },
	{ DIAG_NV_PEEK_F,		"Peek NV Memory" },
	{ DIAG_NV_POKE_F,		"Poke NV Memory" },
	{ DIAG_BAD_CMD_F,		"Bad Command" },
	{ DIAG_BAD_PARM_F,		"Bad Parameter" },
	{ DIAG_BAD_LEN_F,		"Bad Length" },
	{ DIAG_BAD_MODE_F,		"Packet not allowed in current mode" },
	{ DIAG_TAGRAPH_F,		"TA power and voice graphs" },
	{ DIAG_MARKOV_F,		"Markov statistics" },
	{ DIAG_MARKOV_RESET_F,		"Reset Markov statistics" },
	{ DIAG_DIAG_VER_F,		"DIAG Version" },
	{ DIAG_TS_F,			"Timestamp" },
	{ DIAG_TA_PARM_F,		"Set TA Parameters" },
	{ DIAG_MSG_F,			"Request for MSG report" },
	{ DIAG_HS_KEY_F,		"Handset emulation: Keypress" },
	{ DIAG_HS_LOCK_F,		"Handest emulation: Lock/Unlock" },
	{ DIAG_HS_SCREEN_F,		"Handset emulation: Display" },
	{ DIAG_PARM_SET_F,		"Parameter download" },
	{ DIAG_NV_READ_F,		"Read NV item" },
	{ DIAG_NV_WRITE_F,		"Write NV item" },
	{ DIAG_CONTROL_F,		"Mode change request" },
	{ DIAG_ERR_READ_F,		"Error record retrieval" },
	{ DIAG_ERR_CLEAR_F,		"Error record clear" },
	{ DIAG_SER_RESET_F,		"Symbol error rate counter reset" },
	{ DIAG_SER_REPORT_F,		"Symbol error rate counter report" },
	{ DIAG_TEST_F,			"Run a specified test" },
	{ DIAG_GET_DIPSW_F,		"Get current DIP switch setting" },
	{ DIAG_SET_DIPSW_F,		"Write new DIP switch setting" },
	{ DIAG_VOC_PCM_LB_F,		"Start/Stop Vocoder PCM loopback" },
	{ DIAG_VOC_PKT_LB_F,		"Start/Stop Vocoder PKT loopback" },
	{ DIAG_ORIG_F,			"Originate a call" },
	{ DIAG_END_F,			"End a call" },
	{ DIAG_DLOAD_F,			"Switch to downloader" },
	{ DIAG_TMOB_F,			"Test mode and FTM commands" },
	{ DIAG_STATE_F,			"Return phone state" },
	{ DIAG_PILOT_SETS_F,		"Return all current sets of pilots" },
	{ DIAG_SPC_F,			"Send the Service Programming Code" },
	{ DIAG_BAD_SPC_MODE_F,		"Invalid NV read/write because SP is locked" },
	{ DIAG_PARM_GET2_F,		"Get parms" },
	{ DIAG_SERIAL_CHG_F,		"Serial mode change" },
	{ DIAG_PASSWORD_F,		"Send password" },
	{ DIAG_BAD_SEC_MODE_F,		"Bad security mode" },
	{ DIAG_PR_LIST_WR_F,		"Write preferred roaming list to phone" },
	{ DIAG_PR_LIST_RD_F,		"Read preferred roaming list from phone" },
	{ DIAG_SUBSYS_CMD_F,		"Subsystem Command" },
	{ DIAG_FEATURE_QUERY_F,		"Feature Query" },
	{ DIAG_SMS_READ_F,		"Read SMS from NV" },
	{ DIAG_SMS_WRITE_F,		"Write SMS to NV" },
	{ DIAG_SUP_FER_F,		"Frame Error Rate" },
	{ DIAG_SUP_WALSH_CODES_F,	"Supplemental Channel Walsh Codes" },
	{ DIAG_SET_MAX_SUP_CH_F,	"Set max. number of Supplemental Channels" },
	{ DIAG_PARM_GET_IS95B_F,	"Get SUP and MUX2 Params" },
	{ DIAG_FS_OP_F, 		"EFS Operation" },
	{ DIAG_AKEY_VERIFY_F,		"AKEY Verification" },
	{ DIAG_BMP_HS_SCREEN_F,		"Handset emulation: Bitmap screen" },
	{ DIAG_CONFIG_COMM_F,		"Configure communications" },
	{ DIAG_EXT_LOGMASK_F,		"Extended logmask" },
	{ DIAG_EVENT_REPORT_F,		"Event reporting" },
	{ DIAG_STREAMING_CONFIG_F,	"Load Balancing" },
	{ DIAG_PARM_RETRIEVE_F,		"Retrieve Parameter" },
	{ DIAG_STATUS_SNAPSHOT_F,	"State snapshot of DMSS" },
	{ DIAG_RPC_F,			"RPC" },
	{ DIAG_GET_PROPERTY_F,		"Get Property" },
	{ DIAG_PUT_PROPERTY_F,		"Put Property" },
	{ DIAG_GET_GUID_F,		"Get GUID" },
	{ DIAG_USER_CMD_F,		"Invocation of user callbacks" },
	{ DIAG_GET_PERM_PROPERTY_F,	"Get permanent properties" },
	{ DIAG_PUT_PERM_PROPERTY_F,	"Put permanent properties" },
	{ DIAG_PERM_USER_CMD_F,		"Permanent user callbacks" },
	{ DIAG_GPS_SESS_CTRL_F,		"GPS session control" },
	{ DIAG_GPS_GRID_F,		"GPS search grid" },
	{ DIAG_GPS_STATISTICS_F,	"GPS statistics" },
	{ DIAG_ROUTE_F,			"DIAG Packet routing" },
	{ DIAG_IS2000_STATUS_F,		"IS2000 status" },
	{ DIAG_RLP_STAT_RESET_F,	"RPL statistics reset" },
	{ DIAG_TDSO_STAT_RESET_F,	"(S)TDSO statistics reset" },
	{ DIAG_LOG_CONFIG_F,		"Log configuration" },
	{ DIAG_TRACE_EVENT_REPORT_F,	"Trace event reporting" },
	{ DIAG_SBI_READ_F,		"SBI Read" },
	{ DIAG_SBI_WRITE_F,		"SBI Write" },
	{ DIAG_SSD_VERIFY_F,		"SSD Verify" },
	{ DIAG_LOG_ON_DEMAND_F,		"Log on request" },
	{ DIAG_EXT_MSG_F,		"Request extended MSG report" },
	{ DIAG_ONCRPC_F,		"ONCRPC" },
	{ DIAG_PROTOCOL_LOOPBACK_F,	"DIAG Loopback" },
	{ DIAG_EXT_BUILD_ID_F,		"Extended Build ID" },
	{ DIAG_EXT_MSG_CONFIG_F,	"Extended MSG configuration" },
	{ DIAG_EXT_MSG_TERSE_F,		"Extended MSG in terse format" },
	{ DIAG_EXT_MSG_TERSE_XLATE_F,	"Translate terse format MSG identifier" },
	{ DIAG_SUBSYS_CMD_VER_2_F,	"Subsytem dispatcher V2" },
	{ DIAG_EVENT_MASK_GET_F,	"Get event mask" },
	{ DIAG_EVENT_MASK_SET_F,	"Set event mask" },
	{ DIAG_CHANGE_PORT_SETTINGS,	"Change port settings" },
	{ DIAG_CNTRY_INFO_F,		"Country network information" },
	{ DIAG_SUPS_REQ_F,		"Supplementary Service" },
	{ DIAG_MMS_ORIG_SMS_REQUEST_F,	"SMS request for MMS" },
	{ DIAG_MEAS_MODE_F,		"Change measurement mode" },
	{ DIAG_MEAS_REQ_F,		"Request measurements for HDR channels" },
	{ DIAG_QSR_EXT_MSG_TERSE_F,	"Optimized F3 Message" },
	{ DIAG_DCI_CMD_REQ,		"DCI Command" },
	{ DIAG_DCI_DELAYED_RSP,		"DCI Delayed Response" },
	{ DIAG_BAD_TRANS_F,		"DCI Error" },
	{ DIAG_SSM_DISALLOWED_CMD_F,	"SSM Disallowed Command" },
	{ DIAG_LOG_ON_DEMAND_EXT_F,	"Log on extended request" },
	{ DIAG_QSR4_EXT_MSG_TERSE_F,	"QShrink" },
	{ 0, NULL }
};

static value_string_ext qcdiag_cmds_ext = VALUE_STRING_EXT_INIT(qcdiag_cmds);

static const value_string qcdiag_subsys[] = {
	{ DIAG_SUBSYS_OEM,		"OEM" },
	{ DIAG_SUBSYS_ZREX,		"ZREX" },
	{ DIAG_SUBSYS_SD,		"System Determination" },
	{ DIAG_SUBSYS_BT,		"Bluetooth" },
	{ DIAG_SUBSYS_WCDMA,		"WCMDA" },
	{ DIAG_SUBSYS_HDR,		"1xEvDO" },
	{ DIAG_SUBSYS_DIABLO,		"DIABLO" },
	{ DIAG_SUBSYS_TREX,		"TREX - Off-target testing" },
	{ DIAG_SUBSYS_GSM,		"GSM" },
	{ DIAG_SUBSYS_UMTS,		"UMTS" },
	{ DIAG_SUBSYS_HWTC,		"HWTC" },
	{ DIAG_SUBSYS_FTM,		"Factory Test Mode" },
	{ DIAG_SUBSYS_REX,		"REX" },
	{ DIAG_SUBSYS_GPS,		"GPS" },
	{ DIAG_SUBSYS_WMS,		"Wireless Messaging Service" },
	{ DIAG_SUBSYS_CM,		"Call Manager" },
	{ DIAG_SUBSYS_HS,		"Handset" },
	{ DIAG_SUBSYS_AUDIO_SETTINGS,	"Audio Settings" },
	{ DIAG_SUBSYS_DIAG_SERV,	"DIAG Services" },
	{ DIAG_SUBSYS_FS,		"EFS2" },
	{ DIAG_SUBSYS_PORT_MAP_SETTINGS, "Port Map Settings" },
	{ DIAG_SUBSYS_MEDIAPLAYER,	"QCT Mediaplayer" },
	{ DIAG_SUBSYS_QCAMERA,		"QCT QCamera" },
	{ DIAG_SUBSYS_MOBIMON,		"QCT MobiMon" },
	{ DIAG_SUBSYS_GUNIMON,		"QCT GuniMon" },
	{ DIAG_SUBSYS_LSM,		"Location Services Manager" },
	{ DIAG_SUBSYS_QCAMCORDER,	"QCT QCamcorder" },
	{ DIAG_SUBSYS_MUX1X,		"Multiplexer (1x)" },
	{ DIAG_SUBSYS_DATA1X,		"Data (1x)" },
	{ DIAG_SUBSYS_SRCH1X,		"Searcher (1x)" },
	{ DIAG_SUBSYS_CALLP1X,		"Call Processor (1x)" },
	{ DIAG_SUBSYS_APPS,		"Applications" },
	{ DIAG_SUBSYS_SETTINGS,		"Seettings" },
	{ DIAG_SUBSYS_GSDI,		"Generic Sim Driver Interface" },
	{ DIAG_SUBSYS_TMC,		"Task Main Controller" },
	{ DIAG_SUBSYS_USB,		"USB" },
	{ DIAG_SUBSYS_PM,		"Power Management" },
	{ DIAG_SUBSYS_DEBUG,		"Debug" },
	{ DIAG_SUBSYS_CLKRGM,		"Clock Regime" },
	{ DIAG_SUBSYS_WLAN,		"WLAN" },
	{ DIAG_SUBSYS_PS_DATA_LOGGING,	"PS Data Path Logging" },
	{ DIAG_SUBSYS_MFLO,		"MediaFLO" },
	{ DIAG_SUBSYS_DTV,		"Digital TV" },
	{ DIAG_SUBSYS_RRC,		"WCDMA RRC" },
	{ DIAG_SUBSYS_PROF,		"Profiling" },
	{ DIAG_SUBSYS_TCXOMGR,		"TXCO Manager" },
	{ DIAG_SUBSYS_NV,		"NV" },
	{ DIAG_SUBSYS_PARAMS,		"Parameters" },
	{ DIAG_SUBSYS_MDDI,		"MDDI" },
	{ DIAG_SUBSYS_DS_ATCOP,		"Data Services AT Command Processor" },
	{ DIAG_SUBSYS_L4LINUX,		"L4/Linux" },
	{ DIAG_SUBSYS_MVS,		"Multimedia Voice Services" },
	{ DIAG_SUBSYS_CNV,		"Compact NV" },
	{ DIAG_SUBSYS_APIONE_PROGRAM,	"apiOne" },
	{ DIAG_SUBSYS_HIT,		"Hardware Integration Test" },
	{ DIAG_SUBSYS_DRM,		"Digital Restrictions Management" },
	{ DIAG_SUBSYS_DM,		"Device Management" },
	{ DIAG_SUBSYS_FC,		"Flow Controller" },
	{ DIAG_SUBSYS_MEMORY,		"Malloc Manager" },
	{ DIAG_SUBSYS_FS_ALTERNATE,	"Alternate Filesystem" },
	{ DIAG_SUBSYS_REGRESSION,	"Regression Test Commands" },
	{ DIAG_SUBSYS_SENSORS,		"Sensors" },
	{ DIAG_SUBSYS_FLUTE,		"FLUTE" },
	{ DIAG_SUBSYS_ANALOG,		"Analog" },
	{ DIAG_SUBSYS_APIONE_PROGRAM_MODEM, "apine Program on Modem Processor" },
	{ DIAG_SUBSYS_LTE,		"LTE" },
	{ DIAG_SUBSYS_BREW,		"BREW" },
	{ DIAG_SUBSYS_PWRDB,		"Power Debug" },
	{ DIAG_SUBSYS_CHORD,		"Chaos Coordinator" },
	{ DIAG_SUBSYS_SEC,		"Security" },
	{ DIAG_SUBSYS_TIME,		"Time" },
	{ DIAG_SUBSYS_Q6_CORE,		"Q6 Core" },
	{ DIAG_SUBSYS_COREBSP,		"Core BSP" },
	{ DIAG_SUBSYS_MFLO2,		"MediaFLO2" },
	{ DIAG_SUBSYS_ULOG,		"ULog Services" },
	{ DIAG_SUBSYS_APR,		"Async Packet Router" },
	{ DIAG_SUBSYS_QNP,		"QNP" },
	{ DIAG_SUBSYS_STRIDE,		"STRIDE" },
	{ DIAG_SUBSYS_OEMDPP,		"DPP Partition" },
	{ DIAG_SUBSYS_Q5_CORE,		"Q5 Core" },
	{ DIAG_SUBSYS_USCRIPT,		"USCRIPT" },
	{ DIAG_SUBSYS_NAS,		"Non Access Stratum" },
	{ DIAG_SUBSYS_CMAPI,		"CMAPI" },
	{ DIAG_SUBSYS_SSM,		"SSM" },
	{ DIAG_SUBSYS_TDSCDMA,		"TD-SCDMA" },
	{ DIAG_SUBSYS_SSM_TEST,		"SSM Test" },
	{ DIAG_SUBSYS_MPOWER,		"MPOWER" },
	{ DIAG_SUBSYS_QDSS,		"QDSS" },
	{ DIAG_SUBSYS_CXM,		"CXM" },
	{ DIAG_SUBSYS_GNSS_SOC,		"Secondary GNSS" },
	{ DIAG_SUBSYS_TTLITE,		"TTLITE" },
	{ DIAG_SUBSYS_FTM_ANT,		"FTM ANT" },
	{ DIAG_SUBSYS_MLOG,		"MLOG" },
	{ DIAG_SUBSYS_LIMITSMGR,	"LIMITS MGR" },
	{ DIAG_SUBSYS_EFSMONITOR,	"EFS Monitor" },
	{ DIAG_SUBSYS_DISPLAY_CALIBRATION, "Display Calibration" },
	{ DIAG_SUBSYS_VERSION_REPORT,	"Version Report" },
	{ DIAG_SUBSYS_DS_IPA,		"Internet Packet Accelerator" },
	{ DIAG_SUBSYS_SYSTEM_OPERATIONS,	"System Operations" },
	{ DIAG_SUBSYS_CNSS_POWER,	"CNSS Power" },
	{ DIAG_SUBSYS_LWIP,		"LwIP" },
	{ DIAG_SUBSYS_IMS_QVP_RTP,	"IMS QVP RTP" },
	{ 0, NULL }
};

static value_string_ext qcdiag_subsys_ext = VALUE_STRING_EXT_INIT(qcdiag_subsys);

static int
dissect_qcdiag_subsys(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	gint offset = 0;
	guint subsys_id;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "QCDIAG-SUBSYS");

	proto_tree_add_item_ret_uint(tree, hf_qcdiag_subsys_id, tvb, offset++, 1, ENC_NA, &subsys_id);
	proto_tree_add_item(tree, hf_qcdiag_subsys_cmd_code, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	return dissector_try_uint(qcdiag_subsys_dissector_table, subsys_id, tvb, pinfo, tree);
}

static int
dissect_qcdiag(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void * data _U_)
{
	proto_item *ti;
	proto_tree *diag_tree;
	gint offset = 0;
	guint cmd;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "QCDIAG");

	ti = proto_tree_add_item(tree, proto_qcdiag, tvb, 0, -1, ENC_NA);
	diag_tree = proto_item_add_subtree(ti, ett_qcdiag);

	proto_tree_add_item_ret_uint(diag_tree, hf_qcdiag_cmd, tvb, offset, 1, ENC_NA, &cmd);

	switch (cmd) {
	case DIAG_SUBSYS_CMD_F:
		dissect_qcdiag_subsys(tvb, pinfo, diag_tree);
		break;
	default:
		dissector_try_uint(qcdiag_dissector_table, cmd, tvb, pinfo, tree);
		break;
	}

	return tvb_captured_length(tvb);
}

void
proto_register_qcdiag(void)
{
	static hf_register_info hf[] = {
		{ &hf_qcdiag_cmd, { "Command", "qcdiag.cmd",
		  FT_UINT8, BASE_HEX|BASE_EXT_STRING, &qcdiag_cmds_ext, 0, NULL, HFILL } },
		{ &hf_qcdiag_subsys_id, { "Subsystem ID", "qcdiag.subsys_id",
		  FT_UINT8, BASE_DEC|BASE_EXT_STRING, &qcdiag_subsys_ext, 0, NULL, HFILL } },
		{ &hf_qcdiag_subsys_cmd_code, { "Subsystem Command Code", "qcdiag.subsys_cmd_code",
		  FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
	};
	static gint *ett[] = {
		&ett_qcdiag
	};

	proto_qcdiag = proto_register_protocol("Qualcomm DIAG", "QCDIAG", "qcdiag");
	proto_register_field_array(proto_qcdiag, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	qcdiag_dissector_table = register_dissector_table("qcdiag.cmd",
					"QCDIAG Command", proto_qcdiag, FT_UINT8, BASE_DEC);

	qcdiag_subsys_dissector_table = register_dissector_table("qcdiag.subsys_id",
					"QCDIAG Subsystem", proto_qcdiag, FT_UINT8, BASE_DEC);
}

void
proto_reg_handoff_qcdiag(void)
{
	dissector_handle_t qcdiag_handle;

	qcdiag_handle = create_dissector_handle(dissect_qcdiag, proto_qcdiag);
	dissector_add_uint("gsmtap.type", GSMTAP_TYPE_QC_DIAG, qcdiag_handle);
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
