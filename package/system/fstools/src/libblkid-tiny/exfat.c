/*
 * Copyright (C) 2010 Andrew Nayenko <resver@gmail.com>
 *
 * This file may be redistributed under the terms of the
 * GNU Lesser General Public License.
 */
#include "superblocks.h"

struct exfat_super_block {
	uint8_t JumpBoot[3];
	uint8_t FileSystemName[8];
	uint8_t MustBeZero[53];
	uint64_t PartitionOffset;
	uint64_t VolumeLength;
	uint32_t FatOffset;
	uint32_t FatLength;
	uint32_t ClusterHeapOffset;
	uint32_t ClusterCount;
	uint32_t FirstClusterOfRootDirectory;
	uint8_t VolumeSerialNumber[4];
	struct {
		uint8_t vermin;
		uint8_t vermaj;
	} FileSystemRevision;
	uint16_t VolumeFlags;
	uint8_t BytesPerSectorShift;
	uint8_t SectorsPerClusterShift;
	uint8_t NumberOfFats;
	uint8_t DriveSelect;
	uint8_t PercentInUse;
	uint8_t Reserved[7];
	uint8_t BootCode[390];
	uint16_t BootSignature;
} __attribute__((__packed__));

struct exfat_entry_label {
	uint8_t type;
	uint8_t length;
	uint8_t name[22];
	uint8_t reserved[8];
} __attribute__((__packed__));

#define BLOCK_SIZE(sb) ((sb)->BytesPerSectorShift < 32 ? (1u << (sb)->BytesPerSectorShift) : 0)
#define CLUSTER_SIZE(sb) ((sb)->SectorsPerClusterShift < 32 ? (BLOCK_SIZE(sb) << (sb)->SectorsPerClusterShift) : 0)
#define EXFAT_FIRST_DATA_CLUSTER 2
#define EXFAT_LAST_DATA_CLUSTER 0xffffff6
#define EXFAT_ENTRY_SIZE 32

#define EXFAT_ENTRY_EOD		0x00
#define EXFAT_ENTRY_LABEL	0x83

static uint64_t block_to_offset(const struct exfat_super_block *sb,
		uint64_t block)
{
	return block << sb->BytesPerSectorShift;
}

static uint64_t cluster_to_block(const struct exfat_super_block *sb,
		uint32_t cluster)
{
	return le32_to_cpu(sb->ClusterHeapOffset) +
			((uint64_t) (cluster - EXFAT_FIRST_DATA_CLUSTER)
					<< sb->SectorsPerClusterShift);
}

static uint64_t cluster_to_offset(const struct exfat_super_block *sb,
		uint32_t cluster)
{
	return block_to_offset(sb, cluster_to_block(sb, cluster));
}

static uint32_t next_cluster(blkid_probe pr,
		const struct exfat_super_block *sb, uint32_t cluster)
{
	uint32_t *nextp, next;
	uint64_t fat_offset;

	fat_offset = block_to_offset(sb, le32_to_cpu(sb->FatOffset))
		+ (uint64_t) cluster * sizeof(cluster);
	nextp = (uint32_t *) blkid_probe_get_buffer(pr, fat_offset,
			sizeof(uint32_t));
	if (!nextp)
		return 0;
	memcpy(&next, nextp, sizeof(next));
	return le32_to_cpu(next);
}

static struct exfat_entry_label *find_label(blkid_probe pr,
		const struct exfat_super_block *sb)
{
	uint32_t cluster = le32_to_cpu(sb->FirstClusterOfRootDirectory);
	uint64_t offset = cluster_to_offset(sb, cluster);
	uint8_t *entry;
	const size_t max_iter = 10000;
	size_t i = 0;

	for (; i < max_iter; i++) {
		entry = (uint8_t *) blkid_probe_get_buffer(pr, offset,
				EXFAT_ENTRY_SIZE);
		if (!entry)
			return NULL;
		if (entry[0] == EXFAT_ENTRY_EOD)
			return NULL;
		if (entry[0] == EXFAT_ENTRY_LABEL)
			return (struct exfat_entry_label *) entry;

		offset += EXFAT_ENTRY_SIZE;
		if (CLUSTER_SIZE(sb) && (offset % CLUSTER_SIZE(sb)) == 0) {
			cluster = next_cluster(pr, sb, cluster);
			if (cluster < EXFAT_FIRST_DATA_CLUSTER)
				return NULL;
			if (cluster > EXFAT_LAST_DATA_CLUSTER)
				return NULL;
			offset = cluster_to_offset(sb, cluster);
		}
	}

	return NULL;
}

static int probe_exfat(blkid_probe pr, const struct blkid_idmag *mag)
{
	struct exfat_super_block *sb;
	struct exfat_entry_label *label;

	sb = blkid_probe_get_sb(pr, mag, struct exfat_super_block);
	if (!sb || !CLUSTER_SIZE(sb))
		return errno ? -errno : BLKID_PROBE_NONE;

	if (le16_to_cpu(sb->BootSignature) != 0xAA55)
		return BLKID_PROBE_NONE;

	if (memcmp(sb->JumpBoot, "\xEB\x76\x90", 3) != 0)
		return BLKID_PROBE_NONE;

	for (size_t i = 0; i < sizeof(sb->MustBeZero); i++)
		if (sb->MustBeZero[i] != 0x00)
			return BLKID_PROBE_NONE;

	label = find_label(pr, sb);
	if (label)
		blkid_probe_set_utf8label(pr, label->name,
				min((size_t) label->length * 2, sizeof(label->name)),
				BLKID_ENC_UTF16LE);
	else if (errno)
		return -errno;

	blkid_probe_sprintf_uuid(pr, sb->VolumeSerialNumber, 4,
			"%02hhX%02hhX-%02hhX%02hhX",
			sb->VolumeSerialNumber[3], sb->VolumeSerialNumber[2],
			sb->VolumeSerialNumber[1], sb->VolumeSerialNumber[0]);

	blkid_probe_sprintf_version(pr, "%u.%u",
			sb->FileSystemRevision.vermaj, sb->FileSystemRevision.vermin);

#if 0
	blkid_probe_set_fsblocksize(pr, BLOCK_SIZE(sb));
	blkid_probe_set_block_size(pr, BLOCK_SIZE(sb));
	blkid_probe_set_fssize(pr, BLOCK_SIZE(sb) * le64_to_cpu(sb->VolumeLength));
#endif

	return BLKID_PROBE_OK;
}

const struct blkid_idinfo exfat_idinfo =
{
	.name		= "exfat",
	.usage		= BLKID_USAGE_FILESYSTEM,
	.probefunc	= probe_exfat,
	.magics		=
	{
		{ .magic = "EXFAT   ", .len = 8, .sboff = 3 },
		{ NULL }
	}
};
