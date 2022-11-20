#ifndef FILS_H
#define FILS_H

#include "rtdot1x.h"

struct sta_info;
struct apd_data; 
struct ieee80211_mgmt;

int fils_set_tk(struct sta_info *sta);

int fils_decrypt_assoc(struct sta_info *sta,
		       const struct ieee80211_mgmt *mgmt, size_t frame_len,
		       u8 *pos, size_t left);

int fils_encrypt_assoc(struct sta_info *sta, u8 *buf,
		       size_t current_len, size_t max_len,
		       const struct wpabuf *hlp);

void ieee802_11_finish_fils_auth(struct apd_data *hapd,
				 struct sta_info *sta, int success);

u16 send_assoc_resp(struct apd_data *hapd, struct sta_info *sta,
                   const u8 *addr, u16 status_code, int reassoc,
                   const u8 *ies, size_t ies_len);

void handle_auth_fils(struct apd_data *hapd, struct sta_info *sta,
                  const u8 *pos, size_t len, u16 auth_alg,
                  u16 auth_transaction, u16 status_code,
                  void (*cb)(struct apd_data *hapd,
                             struct sta_info *sta, u16 resp,
                             struct wpabuf *data, int pub));

void handle_assoc_fils(struct apd_data *hapd, 
	 struct sta_info *sta, const struct ieee80211_mgmt *mgmt, 
	 size_t len, int reassoc);

void fils_config_default(struct apd_data *hapd);
#endif
