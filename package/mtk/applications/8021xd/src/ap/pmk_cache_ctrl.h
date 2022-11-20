#ifndef PMK_CACHE_CTRL_H
#define PMK_CACHE_CTRL_H

#include "rtdot1x.h"

struct sta_info;
struct apd_data; 

struct _RT_802_PMKSA_CACHE_ENTRY *
pmksa_cache_get(struct apd_data *hapd, struct sta_info *sta, const u8 *pmkid);

int pmksa_cache_add(struct apd_data *hapd, struct sta_info *sta, 
	const u8 *pmk, size_t pmk_len, const u8 *pmkid);

void pmksa_cache_local_free(struct _RT_802_PMKSA_CACHE_ENTRY *pmk_cache);

#endif /* PMK_CACHE_CTRL_H */
