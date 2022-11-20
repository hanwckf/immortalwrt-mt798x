#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <linux/if.h>			/* for IFNAMSIZ and co... */
#include <linux/wireless.h>

#include "includes.h"

#include "common.h"
#include "sta_info.h"
#include "rtmp_type.h"

#include "pmk_cache_ctrl.h"

void pmksa_cache_local_free(struct _RT_802_PMKSA_CACHE_ENTRY *pmk_cache)
{
	struct _RT_802_PMKSA_CACHE_ENTRY *prev;

	while (pmk_cache) {
		prev = pmk_cache;
		pmk_cache = pmk_cache->next;
		free(prev);
	}
}

static struct _RT_802_PMKSA_CACHE_ENTRY *
pmksa_cache_local_handle(struct apd_data *hapd, struct sta_info *sta, 
	const u8 *pmk, size_t pmk_len, const u8 *pmkid)
{
	struct _RT_802_PMKSA_CACHE_ENTRY * pmksa = NULL;

	pmksa = hapd->pmk_cache;
	while (pmksa) {
		if ((memcmp(pmksa->addr, sta->addr, ETH_ALEN) == 0) && 
			(pmksa->apIdx == sta->ApIdx) &&
			(memcmp(pmksa->pmkid, pmkid, PMKID_LEN) == 0)) {

			/* re-fill ? */
			pmksa->pmk_len = pmk_len;
			memcpy(pmksa->pmk, pmk, pmksa->pmk_len);
			
			return pmksa;
		}

		pmksa = pmksa->next;
	}

	pmksa = os_zalloc(sizeof(struct _RT_802_PMKSA_CACHE_ENTRY));
	if (!pmksa) {
		DBGPRINT(RT_DEBUG_ERROR,"MEM Error in %s\n", __func__);
		return NULL;
	}
	
	memcpy(pmksa->addr, sta->addr, MAC_ADDR_LEN);
	memcpy(pmksa->pmkid, pmkid, PMKID_LEN);
	pmksa->apIdx = sta->ApIdx;
	pmksa->pmk_len = pmk_len;
	memcpy(pmksa->pmk, pmk, pmksa->pmk_len);

	/* update the new one into list */
	pmksa->next = hapd->pmk_cache;
	hapd->pmk_cache = pmksa;
	
	return pmksa;
}

struct _RT_802_PMKSA_CACHE_ENTRY *
pmksa_cache_get(struct apd_data *hapd, struct sta_info *sta, const u8 *pmkid)
{
	struct _RT_802_PMKSA_CACHE_ENTRY * pmksa = NULL;
	RT_802_11_PMK_CACHE_SYNC_EVENT pmk_cache_event;	
    int ret = 0;

	pmksa = hapd->pmk_cache;
	while (pmksa) {
		if ((memcmp(pmksa->addr, sta->addr, ETH_ALEN) == 0) && 
			(pmksa->apIdx == sta->ApIdx) &&
			(memcmp(pmksa->pmkid, pmkid, PMKID_LEN) == 0)) {
			
			return pmksa;
		}

		pmksa = pmksa->next;
	}

	memset(&pmk_cache_event, 0, sizeof(pmk_cache_event));

	pmk_cache_event.res = PMK_CACHE_QUERY;
    memcpy(pmk_cache_event.addr, sta->addr, MAC_ADDR_LEN);
	memcpy(pmk_cache_event.pmkid, pmkid, PMKID_LEN);

	ret = RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&pmk_cache_event, 
		sizeof(RT_802_11_PMK_CACHE_SYNC_EVENT), hapd->prefix_wlan_name, sta->ApIdx, 
		RT_OID_802_DOT1X_PMK_CACHE_EVENT);

    if (ret < 0) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to pmksa_cache_get (addr " MACSTR
                       " reason %d)\n",
                       __func__, MAC2STR(sta->addr), ret);
			return NULL;
    }

	/* sync to local cache */
   	if (pmk_cache_event.res) {		
		return pmksa_cache_local_handle(hapd, sta, pmk_cache_event.pmk,
			pmk_cache_event.pmk_len, pmkid);
   	}
	
	return NULL;
}

int pmksa_cache_add(struct apd_data *hapd, struct sta_info *sta, 
	const u8 *pmk, size_t pmk_len, const u8 *pmkid)
{
#if 1
	struct _RT_802_PMKSA_CACHE_ENTRY * pmksa = NULL;
	pmksa = pmksa_cache_local_handle(hapd, sta, pmk, pmk_len, pmkid);

	if (pmksa == NULL)
		return -1;

	return 0;
#else
	RT_802_11_PMK_CACHE_SYNC_EVENT pmk_cache_event;	
    int ret = 0;
	
	memset(&pmk_cache_event, 0, sizeof(pmk_cache_event));

	pmk_cache_event.res = PMK_CACHE_ADD;
    memcpy(pmk_cache_event.addr, sta->addr, MAC_ADDR_LEN);
	memcpy(pmk_cache_event.pmkid, pmkid, PMKID_LEN);
	pmk_cache_event.pmk_len = pmk_len;
	memcpy(pmk_cache_event.pmk, pmk, pmk_cache_event.pmk_len);

	ret = RT_ioctl(hapd->ioctl_sock, RT_PRIV_IOCTL, (char *)&pmk_cache_event, 
		sizeof(RT_802_11_PMK_CACHE_SYNC_EVENT), hapd->prefix_wlan_name, sta->ApIdx, 
		RT_OID_802_DOT1X_MLME_EVENT);

    if (ret < 0) {
            DBGPRINT(RT_DEBUG_ERROR, "%s: Failed to pmksa_cache_get (addr " MACSTR
                       " reason %d)\n",
                       __func__, MAC2STR(sta->addr), ret);
			return ret;
    }

	/* sync to local cache */
   	if (pmk_cache_event.res) {		
		pmksa_cache_local_handle(hapd, sta, pmk_cache_event.pmk,
			pmk_cache_event.pmk_len, pmkid);

		return 0;
   	}
	
	return -1;
#endif		
}
