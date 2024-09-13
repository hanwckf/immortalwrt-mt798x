#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <lauxlib.h>
#include <lua.h>
#include <luaconf.h>
#include <lualib.h>

#include "iwinfo.h"
#include "mtwifi.h"

static char luacmd[500];

static const char dev2chip[] = 
	"local l1parser = require 'l1util'\n"
	"local l1dat = l1parser.load_l1_profile(l1parser.L1_DAT_PATH)\n"
	"return l1dat.devname_ridx.%s.INDEX\n";

static const char ifname2chip[] = 
	"local l1parser = require 'l1util'\n"
	"local l1dat = l1parser.load_l1_profile(l1parser.L1_DAT_PATH)\n"
	"return l1dat.ifname_ridx.%s.INDEX\n";

#if defined(LUA_VERSION_NUM) && LUA_VERSION_NUM == 501
static int lua_absindex (lua_State *L, int i) {
	if (i < 0 && i > LUA_REGISTRYINDEX)
		i += lua_gettop(L) + 1;
	return i;
}
#endif

#if defined( LUA_VERSION_NUM ) && LUA_VERSION_NUM <= 502
#define lua_getfield(L, i, k) \
	(lua_getfield((L), (i), (k)), lua_type((L), -1))

static int luaL_getsubtable (lua_State *L, int i, const char *name) {
	int abs_i = lua_absindex(L, i);
	luaL_checkstack(L, 3, "not enough stack slots");
	lua_pushstring(L, name);
	lua_gettable(L, abs_i);
	if (lua_istable(L, -1))
		return 1;
	lua_pop(L, 1);
	lua_newtable(L);
	lua_pushstring(L, name);
	lua_pushvalue(L, -2);
	lua_settable(L, abs_i);
	return 0;
}

static void luaL_requiref (lua_State *L, const char *modname,
		lua_CFunction openf, int glb) {
	luaL_checkstack(L, 3, "not enough stack slots available");
	luaL_getsubtable(L, LUA_REGISTRYINDEX, "_LOADED");
	if (lua_getfield(L, -1, modname) == LUA_TNIL) {
		lua_pop(L, 1);
		lua_pushcfunction(L, openf);
		lua_pushstring(L, modname);
		lua_call(L, 1, 1);
		lua_pushvalue(L, -1);
		lua_setfield(L, -3, modname);
	}

	if (glb) {
		lua_pushvalue(L, -1);
		lua_setglobal(L, modname);
	}
	lua_replace(L, -2);
}
#endif

static int openf(lua_State* L) {
	int ret;
	ret = luaL_dofile(L, MTK_L1UTIL_PATH);
	return 1;
}

static int mtk_dev_match_id(const char* chip, struct iwinfo_hardware_id *id)
{
	if (!strcmp(chip, "MT7981")) {
		id->vendor_id = 0x14c3;
		id->device_id = 0x7981;
		id->subsystem_vendor_id = id->vendor_id;
		id->subsystem_device_id = id->device_id;
	} else if (!strcmp(chip, "MT7986")) {
		id->vendor_id = 0x14c3;
		id->device_id = 0x7986;
		id->subsystem_vendor_id = id->vendor_id;
		id->subsystem_device_id = id->device_id;
	} else if (!strcmp(chip, "MT7916")) {
		id->vendor_id = 0x14c3;
		id->device_id = 0x7916;
		id->subsystem_vendor_id = id->vendor_id;
		id->subsystem_device_id = id->device_id;
	} else {
		return -1;
	}

	return 0;
}

int mtk_get_id_by_l1util(const char *dev, struct iwinfo_hardware_id *id)
{
	int ret;
	int is_ifname = 0;

	if (access(MTK_L1UTIL_PATH, F_OK) != 0)
		return -1;

	if (strstr(dev,"ra") || strstr(dev,"apcli") || strstr(dev,"wds") || strstr(dev,"mesh"))
		is_ifname = 1;

	lua_State* L = luaL_newstate();

	luaL_openlibs(L);
	luaL_requiref(L, "l1util", openf, 0);

	if (is_ifname)
		snprintf(luacmd, sizeof(luacmd), ifname2chip, dev);
	else
		snprintf(luacmd, sizeof(luacmd), dev2chip, dev);

	ret = luaL_dostring(L, luacmd);

	if (ret == 0)
		ret = mtk_dev_match_id(lua_tostring(L, -1), id);

	lua_close(L);

	return ret;
}

static int mtk_get_l1profile_attr(const char *attr, char *data, int len)
{
	FILE *fp;
	char *key, *val, buf[512];

	fp = fopen(MTK_L1_PROFILE_PATH, "r");
	if (!fp)
		return -1;

	while (fgets(buf, sizeof(buf), fp))
	{
		key = strtok(buf, " =\n");
		val = strtok(NULL, "\n");
		
		if (!key || !val || !*key || *key == '#')
			continue;

		if (!strcmp(key, attr))
		{
			//printf("l1profile key=%s, val=%s\n", key, val);
			snprintf(data, len, "%s", val);
			fclose(fp);
			return 0;
		}
	}

	fclose(fp);
	return -1;
}

int mtk_get_id_from_l1profile(struct iwinfo_hardware_id *id)
{
	char buf[16] = {0};

	/* if l1profile has INDEX1, return error*/
	if (mtk_get_l1profile_attr("INDEX1", buf, sizeof(buf)) == 0)
		return -1;

	if (mtk_get_l1profile_attr("INDEX0", buf, sizeof(buf)) != 0)
		return -1;

	return (mtk_dev_match_id(buf, id));
}
