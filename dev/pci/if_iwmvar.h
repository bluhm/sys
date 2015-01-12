/* Copyright (c) 2014 Fixup Software Ltd.  All rights reserved */

/*
 * Some bits in here are semi-derived from iwlwifi and iwn drivers
 */

#define IWM_UCODE_SECT_MAX 6
#define IWM_FWNAME "iwlwifi-7260-9.ucode"
#define IWM_FWDMASEGSZ (192*1024)
/* sanity check value */
#define IWM_FWMAXSIZE (2*1024*1024)

/*
 * fw_status is used to determine if we've already parsed the firmware file
 *
 * In addition to the following, status < 0 ==> -error
 */
#define FW_STATUS_NONE		0
#define FW_STATUS_INPROGRESS	1
#define FW_STATUS_DONE		2

enum iwm_ucode_type {
	IWM_UCODE_TYPE_INIT,
	IWM_UCODE_TYPE_REGULAR,
	IWM_UCODE_TYPE_WOW,
	IWM_UCODE_TYPE_MAX
};

struct iwm_fw_info {
	void *fw_rawdata;
	size_t fw_rawsize;
	int fw_status;

	struct fw_sects {
		struct fw_onesect {
			void *fws_data;
			uint32_t fws_len;
			uint32_t fws_devoff; 

			void *fws_alloc;
			size_t fws_allocsize;
		} fw_sect[IWM_UCODE_SECT_MAX];
		size_t fw_totlen;
		int fw_count;
	} fw_sects[IWM_UCODE_TYPE_MAX];
};

struct iwm_nvm_data {
	int n_hw_addrs;
	uint8_t hw_addr[ETHER_ADDR_LEN];

	uint8_t calib_version;
	uint16_t calib_voltage;

	uint16_t raw_temperature;
	uint16_t kelvin_temperature;
	uint16_t kelvin_voltage;
	uint16_t xtal_calib[2];

	bool sku_cap_band_24GHz_enable;
	bool sku_cap_band_52GHz_enable;
	bool sku_cap_11n_enable;
	bool sku_cap_amt_enable;
	bool sku_cap_ipan_enable;

	uint8_t radio_cfg_type;
	uint8_t radio_cfg_step;
	uint8_t radio_cfg_dash;
	uint8_t radio_cfg_pnum;
	uint8_t valid_tx_ant, valid_rx_ant;

	uint16_t nvm_version;
	uint8_t max_tx_pwr_half_dbm;
};

/* max bufs per tfd the driver will use */
#define IWM_MAX_CMD_TBS_PER_TFD 2

struct iwl_rx_packet;
struct iwm_host_cmd {
	const void *data[IWM_MAX_CMD_TBS_PER_TFD];
	struct iwl_rx_packet *resp_pkt;
	unsigned long _rx_page_addr;
	uint32_t _rx_page_order;
	int handler_status;

	uint32_t flags;
	uint16_t len[IWM_MAX_CMD_TBS_PER_TFD];
	uint8_t dataflags[IWM_MAX_CMD_TBS_PER_TFD];
	uint8_t id;
};

/*
 * DMA glue is from iwn
 */

#ifdef __OpenBSD__
typedef caddr_t iwm_caddr_t;
typedef void *iwm_hookarg_t;
#else
typedef void * iwm_caddr_t;
typedef struct device *iwm_hookarg_t;
#endif

struct iwm_dma_info {
	bus_dma_tag_t		tag;
	bus_dmamap_t		map;
	bus_dma_segment_t	seg;
	bus_addr_t		paddr;
	void 			*vaddr;
	bus_size_t		size;
};

#define IWM_TX_RING_COUNT	256
#define IWM_TX_RING_LOMARK	192
#define IWM_TX_RING_HIMARK	224

struct iwm_tx_data {
	bus_dmamap_t	map;
	bus_addr_t	cmd_paddr;
	bus_addr_t	scratch_paddr;
	struct mbuf	*m;
	struct iwm_node *in;
	bool done;
};

struct iwm_tx_ring {
	struct iwm_dma_info	desc_dma;
	struct iwm_dma_info	cmd_dma;
	struct iwl_tfd		*desc;
	struct iwl_device_cmd	*cmd;
	struct iwm_tx_data	data[IWM_TX_RING_COUNT];
	int			qid;
	int			queued;
	int			cur;
};

#define IWM_RX_RING_COUNT	256
#define IWM_RBUF_COUNT		(IWM_RX_RING_COUNT + 32)
/* Linux driver optionally uses 8k buffer */
#define IWM_RBUF_SIZE		4096

struct iwm_softc;
struct iwm_rbuf {
	struct iwm_softc	*sc;
	void			*vaddr;
	bus_addr_t		paddr;
};

struct iwm_rx_data {
	struct mbuf	*m;
	bus_dmamap_t	map;
	int		wantresp;
};

struct iwm_rx_ring {
	struct iwm_dma_info	desc_dma;
	struct iwm_dma_info	stat_dma;
	struct iwm_dma_info	buf_dma;
	uint32_t		*desc;
	struct iwl_rb_status	*stat;
	struct iwm_rx_data	data[IWM_RX_RING_COUNT];
	int			cur;
};

#define IWM_FLAG_USE_ICT	0x01
#define IWM_FLAG_HW_INITED	0x02
#define IWM_FLAG_STOPPED	0x04
#define IWM_FLAG_RFKILL		0x08

struct iwm_ucode_status {
	uint32_t uc_error_event_table;
	uint32_t uc_log_event_table;
	
	bool uc_ok;
	bool uc_intr;
};

#define IWM_CMD_RESP_MAX PAGE_SIZE

#define OTP_LOW_IMAGE_SIZE 2048

#define IWM_MVM_TE_SESSION_PROTECTION_MAX_TIME_MS 500
#define IWM_MVM_TE_SESSION_PROTECTION_MIN_TIME_MS 400

/*
 * Command headers are in iwl-trans.h, which is full of all
 * kinds of other junk, so we just replicate the structures here.
 * First the software bits:
 */
enum CMD_MODE {
	CMD_SYNC		= 0,
	CMD_ASYNC		= BIT(0),
	CMD_WANT_SKB		= BIT(1),
	CMD_SEND_IN_RFKILL	= BIT(2),
};
enum iwm_hcmd_dataflag {
        IWL_HCMD_DFL_NOCOPY     = BIT(0),
        IWL_HCMD_DFL_DUP        = BIT(1),
};

/*
 * iwlwifi/iwl-phy-db
 */

#define IWL_NUM_PAPD_CH_GROUPS	4
#define IWL_NUM_TXP_CH_GROUPS	9

struct iwm_phy_db_entry {
	uint16_t size;
	uint8_t *data;
};

struct iwm_phy_db {
	struct iwm_phy_db_entry	cfg;
	struct iwm_phy_db_entry	calib_nch;
	struct iwm_phy_db_entry	calib_ch_group_papd[IWL_NUM_PAPD_CH_GROUPS];
	struct iwm_phy_db_entry	calib_ch_group_txp[IWL_NUM_TXP_CH_GROUPS];
};

struct iwm_int_sta {
	uint32_t sta_id;
	uint32_t tfd_queue_msk;
};

struct iwm_mvm_phy_ctxt {
	uint16_t id;
	uint16_t color;
	uint32_t ref;
	struct ieee80211_channel *channel;
};

struct iwm_bf_data {
	bool bf_enabled;		/* filtering	*/
	bool ba_enabled;		/* abort	*/
	int ave_beacon_signal;
	int last_cqm_event;
};

struct iwm_softc {
#ifdef __OpenBSD__
	struct device sc_devstore;
	struct device *sc_dev;
#else
	struct device *sc_dev;
	struct ethercom sc_ec;
#endif

	struct ieee80211com sc_ic;
	int (*sc_newstate)(struct ieee80211com *, enum ieee80211_state, int);
	int sc_newstate_pending;

	struct ieee80211_amrr sc_amrr;
#ifdef __OpenBSD__
	struct timeout sc_calib_to;
#else
	struct callout sc_calib_to;
#endif

	bus_space_tag_t sc_bst;
	bus_space_handle_t sc_bsh;
	bus_size_t sc_sz;
	bus_dma_tag_t sc_dmat;
	pci_chipset_tag_t sc_pct;
	pcitag_t sc_pcitag;
	const void *sc_ih;

	/* TX scheduler rings. */
	struct iwm_dma_info		sched_dma;
	uint32_t			sched_base;

        /* TX/RX rings. */
	struct iwm_tx_ring txq[IWL_MVM_MAX_QUEUES];
	struct iwm_rx_ring rxq;
	int qfullmsk;

	int sc_sf_state;

        /* ICT table. */
	struct iwm_dma_info	ict_dma;
	int			ict_cur;

	int sc_hw_rev;
	int sc_hw_id;

	struct iwm_dma_info kw_dma;
	struct iwm_dma_info fw_dma;

	bool sc_fw_chunk_done;
	bool sc_init_complete;

	struct iwm_ucode_status sc_uc;
	enum iwl_ucode_type sc_uc_current;
	int sc_fwver;

	int sc_capaflags;
	int sc_capa_max_probe_len;

	int sc_intmask;
	int sc_flags;

	/*
	 * So why do we need a separate stopped flag and a generation?
	 * the former protects the device from issueing commands when it's
	 * stopped (duh).  The latter protects against race from a very
	 * fast stop/unstop cycle where threads waiting for responses do
	 * not have a chance to run in between.  Notably: we want to stop
	 * the device from interrupt context when it craps out, so we
	 * don't have the luxury of waiting for quiescense.
	 */
	int sc_generation;

	int sc_cap_off; /* PCIe caps */

	const char *sc_fwname;
	bus_size_t sc_fwdmasegsz;
	struct iwm_fw_info sc_fw;
	int sc_fw_phy_config;
	struct iwl_tlv_calib_ctrl sc_default_calib[IWL_UCODE_TYPE_MAX];

	struct iwm_nvm_data sc_nvm;
	struct iwm_phy_db sc_phy_db;

	struct iwm_bf_data sc_bf;

	int sc_tx_timer;

	struct iwl_scan_cmd *sc_scan_cmd;
	size_t sc_scan_cmd_len;
	int sc_scan_last_antenna;
	int sc_scanband;

	int sc_auth_prot;

	int sc_fixed_ridx;

	int sc_staid;
	int sc_nodecolor;

	uint8_t sc_cmd_resp[IWM_CMD_RESP_MAX];
	int sc_wantresp;

#ifdef __OpenBSD__
	struct workq *sc_nswq, *sc_eswq;
	struct workq_task sc_eswk;
#else
	struct workqueue *sc_nswq, *sc_eswq;
	struct work sc_eswk;
#endif

	struct iwl_rx_phy_info sc_last_phy_info;
	int sc_ampdu_ref;

	struct iwm_int_sta sc_aux_sta;

	/* phy contexts.  we only use the first one */
	struct iwm_mvm_phy_ctxt sc_phyctxt[NUM_PHY_CTX];

	struct iwl_notif_statistics sc_stats;
};

struct iwm_node {
	struct ieee80211_node in_ni;
	struct iwm_mvm_phy_ctxt *in_phyctxt;

	uint16_t in_id;
	uint16_t in_color;
	int in_tsfid;

	/* status "bits" */
	bool in_assoc;

	struct iwl_lq_cmd in_lq;
	struct ieee80211_amrr_node in_amn;

	uint8_t in_ridx[IEEE80211_RATE_MAXSIZE];
};
#define IWM_STATION_ID 0

#define IWM_ICT_SIZE		4096
#define IWM_ICT_COUNT		(IWM_ICT_SIZE / sizeof (uint32_t))
#define IWM_ICT_PADDR_SHIFT	12
