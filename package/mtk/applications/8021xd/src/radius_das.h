struct rtapd_config;
struct apd_data;

struct radius_das_data {
	int port;
	int sock;
	u8 *shared_secret;
	size_t shared_secret_len;
	struct in_addr client_addr;
	unsigned int time_window;
	int require_event_timestamp;
};

enum radius_das_res {
	RADIUS_DAS_SUCCESS,
	RADIUS_DAS_NAS_MISMATCH,
	RADIUS_DAS_SESSION_NOT_FOUND,
	RADIUS_DAS_MULTI_SESSION_MATCH,
};

struct radius_das_attrs {
	/* NAS identification attributes */
	const u8 *nas_ip_addr;
	const u8 *nas_identifier;
	size_t nas_identifier_len;
	const u8 *nas_ipv6_addr;

	/* Session identification attributes */
	const u8 *sta_addr;
	const u8 *user_name;
	size_t user_name_len;
	const u8 *acct_session_id;
	size_t acct_session_id_len;
	const u8 *acct_multi_session_id;
	size_t acct_multi_session_id_len;
	const u8 *cui;
	size_t cui_len;
};

int radius_das_init(struct apd_data *rtapd);

void radius_das_deinit(struct rtapd_config *conf);

