cmake_minimum_required(VERSION 2.6)

PROJECT(fs-tools C)
ADD_DEFINITIONS(-Os -ggdb -Wall -Werror --std=gnu99 -Wmissing-declarations -Wno-format-truncation)

SET(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")

ADD_LIBRARY(fstools SHARED
		libfstools/common.c
		libfstools/snapshot.c
		libfstools/extroot.c
		libfstools/overlay.c
		libfstools/volume.c
		libfstools/mtd.c
		libfstools/mount.c
		libfstools/ubi.c
		libfstools/rootdisk.c
		libfstools/partname.c
		libfstools/find.c)
TARGET_LINK_LIBRARIES(fstools ubox)
INSTALL(TARGETS fstools LIBRARY DESTINATION lib)

ADD_LIBRARY(blkid-tiny SHARED
		libblkid-tiny/encode.c
		libblkid-tiny/libblkid-tiny.c
		libblkid-tiny/mkdev.c
		libblkid-tiny/probe.c
		libblkid-tiny/exfat.c
		libblkid-tiny/ext.c
		libblkid-tiny/jffs2.c
		libblkid-tiny/vfat.c
		libblkid-tiny/ntfs.c
		libblkid-tiny/hfs.c
		libblkid-tiny/swap.c
		libblkid-tiny/ubi.c
		libblkid-tiny/ubifs.c
		libblkid-tiny/squashfs.c
		libblkid-tiny/btrfs.c
		libblkid-tiny/f2fs.c
		)
INSTALL(TARGETS blkid-tiny LIBRARY DESTINATION lib)
INSTALL(FILES libblkid-tiny/libblkid-tiny.h DESTINATION include)

ADD_LIBRARY(ubi-utils STATIC
		libubi/libubi.c
		libubi/libubi-tiny.c
		libubi/ubiutils-common.c)
INSTALL(TARGETS ubi-utils ARCHIVE DESTINATION lib)

FIND_PATH(ubox_include_dir libubox/ulog.h)
INCLUDE_DIRECTORIES(${ubox_include_dir})

SET_TARGET_PROPERTIES(ubi-utils PROPERTIES COMPILE_FLAGS
		"-ffunction-sections -fdata-sections")

INSTALL(FILES libubi/libubi-tiny.h libubi/libubi.h libubi/ubi-media.h
		libubi/ubi-user.h libubi/ubi-media.h
	DESTINATION include
)

IF(DEFINED CMAKE_OVL_MOUNT_COMPRESS_ZLIB)
	ADD_DEFINITIONS(-DOVL_MOUNT_COMPRESS_ZLIB)
ENDIF(DEFINED CMAKE_OVL_MOUNT_COMPRESS_ZLIB)

IF(DEFINED CMAKE_OVL_MOUNT_FULL_ACCESS_TIME)
	ADD_DEFINITIONS(-DOVL_MOUNT_FULL_ACCESS_TIME)
ENDIF(DEFINED CMAKE_OVL_MOUNT_FULL_ACCESS_TIME)

ADD_EXECUTABLE(mount_root mount_root.c)
TARGET_LINK_LIBRARIES(mount_root fstools)
INSTALL(TARGETS mount_root RUNTIME DESTINATION sbin)

find_library(json NAMES json-c json)

ADD_EXECUTABLE(blockd blockd.c)
TARGET_LINK_LIBRARIES(blockd fstools ubus blobmsg_json ${json})
INSTALL(TARGETS blockd RUNTIME DESTINATION sbin)

ADD_EXECUTABLE(block block.c probe.c probe-libblkid.c)
IF(DEFINED CMAKE_UBIFS_EXTROOT)
	ADD_DEFINITIONS(-DUBIFS_EXTROOT)
	TARGET_LINK_LIBRARIES(block blkid-tiny dl uci ubox ubus blobmsg_json ubi-utils ${json})
ELSE(DEFINED CMAKE_UBIFS_EXTROOT)
	TARGET_LINK_LIBRARIES(block blkid-tiny dl uci ubox ubus blobmsg_json ${json})
ENDIF(DEFINED CMAKE_UBIFS_EXTROOT)
INSTALL(TARGETS block RUNTIME DESTINATION sbin)

ADD_EXECUTABLE(jffs2reset jffs2reset.c)
TARGET_LINK_LIBRARIES(jffs2reset fstools)
INSTALL(TARGETS jffs2reset RUNTIME DESTINATION sbin)

ADD_EXECUTABLE(snapshot_tool snapshot.c)
TARGET_LINK_LIBRARIES(snapshot_tool fstools)
INSTALL(TARGETS snapshot_tool RUNTIME DESTINATION sbin)

ADD_EXECUTABLE(ubi ubi.c)
TARGET_LINK_LIBRARIES(ubi ubi-utils ubox)
INSTALL(TARGETS ubi RUNTIME DESTINATION sbin)
