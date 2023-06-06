RAMFS_COPY_BIN='mkfs.f2fs blkid blockdev fw_printenv fw_setenv'
RAMFS_COPY_DATA="/etc/fw_env.config /var/lock/fw_printenv.lock"

xiaomi_wr30u_initial_setup()
{
	# initialize UBI and setup uboot-env if it's running on initramfs
	[ "$(rootfs_type)" = "tmpfs" ] || return 0

	local mtdnum="$( find_mtd_index ubi )"
	if [ ! "$mtdnum" ]; then
		echo "unable to find mtd partition ubi"
		return 1
	fi

	local kern_mtdnum="$( find_mtd_index ubi_kernel )"
	if [ ! "$kern_mtdnum" ]; then
		echo "unable to find mtd partition ubi_kernel"
		return 1
	fi

	ubidetach -m "$mtdnum"
	ubiformat /dev/mtd$mtdnum -y

	ubidetach -m "$kern_mtdnum"
	ubiformat /dev/mtd$kern_mtdnum -y

	if ! fw_printenv -n flag_try_sys2_failed &>/dev/null; then
		echo "failed to access u-boot-env. skip env setup."
		return 0
	fi

	fw_setenv boot_wait on
	fw_setenv uart_en 1
	fw_setenv flag_boot_rootfs 0
	fw_setenv flag_last_success 1
	fw_setenv flag_boot_success 1
	fw_setenv flag_try_sys1_failed 8
	fw_setenv flag_try_sys2_failed 8

	local board=$(board_name)
	case "$board" in
	xiaomi,mi-router-wr30u-stock)
		fw_setenv mtdparts "nmbm0:1024k(bl2),256k(Nvram),256k(Bdata),2048k(factory),2048k(fip),256k(crash),256k(crash_log),34816k(ubi),34816k(ubi1),32768k(overlay),12288k(data),256k(KF)"
		;;
	esac
}

platform_do_upgrade() {
	local board=$(board_name)

	case "$board" in
	xiaomi,mi-router-wr30u-112m|\
	*mt3000* |\
	*x3000* |\
	*xe3000* |\
	*mt2500* |\
	*zr-3020* |\
	*360,t7* |\
	*cetron,ct3003* |\
	*jcg,q30* |\
	*snand*)
		nand_do_upgrade "$1"
		;;
	*emmc*)
		mtk_mmc_do_upgrade "$1"
		;;
	xiaomi,mi-router-wr30u-stock)
		CI_KERN_UBIPART=ubi_kernel
		CI_ROOT_UBIPART=ubi
		nand_do_upgrade "$1"
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
	*mt3000* |\
	*x3000* |\
	*xe3000* |\
	*mt2500* |\
	*zr-3020* |\
	*360,t7* |\
	xiaomi,mi-router-wr30u-stock|\
	xiaomi,mi-router-wr30u-112m|\
	*cetron,ct3003* |\
	*jcg,q30* |\
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

platform_pre_upgrade() {
	local board=$(board_name)

	case "$board" in
	xiaomi,mi-router-wr30u-stock)
		xiaomi_wr30u_initial_setup
		;;
	esac
}
