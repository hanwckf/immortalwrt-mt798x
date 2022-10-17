RAMFS_COPY_BIN='mkfs.f2fs blkid blockdev fw_printenv fw_setenv'
RAMFS_COPY_DATA="/etc/fw_env.config /var/lock/fw_printenv.lock"

platform_do_upgrade() {
	local board=$(board_name)

	case "$board" in
	*snand*)
		nand_do_upgrade "$1"
		;;
	*emmc*)
		mtk_mmc_do_upgrade "$1"
		;;
	*)
		default_do_upgrade "$1"
		;;
	esac
}

PART_NAME=firmware

platform_check_image() {
	local board=$(board_name)
	local magic="$(get_magic_long "$1")"

	[ "$#" -gt 1 ] && return 1

	case "$board" in
	*snand* |\
	*emmc*)
		# tar magic `ustar`
		magic="$(dd if="$1" bs=1 skip=257 count=5 2>/dev/null)"

		[ "$magic" != "ustar" ] && {
			echo "Invalid image type."
			return 1
		}

		return 0
		;;
	*)
		[ "$magic" != "d00dfeed" ] && {
			echo "Invalid image type."
			return 1
		}
		return 0
		;;
	esac

	return 0
}
