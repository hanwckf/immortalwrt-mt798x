
# Keep these values be up-to-date with definition in libfstools/rootdisk.c of fstools package
ROOTDEV_OVERLAY_ALIGN=$((64*1024))
F2FS_MINSIZE=$((100*1024*1024))

mtk_get_root() {
	local rootfsdev

	if read cmdline < /proc/cmdline; then
		case "$cmdline" in
			*root=*)
				rootfsdev="${cmdline##*root=}"
				rootfsdev="${rootfsdev%% *}"
			;;
		esac

		echo "${rootfsdev}"
	fi
}

block_dev_path() {
	local dev_path

	case "$1" in
	/dev/mmcblk*)
		dev_path="$1"
		;;
	PARTLABEL=* | PARTUUID=*)
		dev_path=$(blkid -t "$1" -o device)
		[ -z "${dev_path}" -o $? -ne 0 ] && return 1
		;;
	*)
		return 1;
		;;
	esac

	echo "${dev_path}"
	return 0
}

mmc_upgrade_tar() {
	local tar_file="$1"
	local kernel_dev="$2"
	local rootfs_dev="$3"

	local board_dir=$(tar tf ${tar_file} | grep -m 1 '^sysupgrade-.*/$')
	board_dir=${board_dir%/}

	local kernel_length=$( (tar xf $tar_file ${board_dir}/kernel -O | wc -c) 2> /dev/null)
	local rootfs_length=$( (tar xf $tar_file ${board_dir}/root -O | wc -c) 2> /dev/null)

	[ "${kernel_length}" != 0 ] && {
		tar xf ${tar_file} ${board_dir}/kernel -O >${kernel_dev}
	}

	[ "${rootfs_length}" != 0 ] && {
		tar xf ${tar_file} ${board_dir}/root -O >${rootfs_dev}
	}

	local rootfs_dev_size=$(blockdev --getsize64 ${rootfs_dev})
	[ $? -ne 0 ] && return 1

	local rootfs_data_offset=$(((rootfs_length+ROOTDEV_OVERLAY_ALIGN-1)&~(ROOTDEV_OVERLAY_ALIGN-1)))
	local rootfs_data_size=$((rootfs_dev_size-rootfs_data_offset))

	local loopdev="$(losetup -f)"
	losetup -o $rootfs_data_offset $loopdev $rootfs_dev || {
		v "Failed to mount looped rootfs_data."
		return 1
	}

	local fstype=ext4
	local mkfs_arg="-q -L rootfs_data"
	[ "${rootfs_data_size}" -gt "${F2FS_MINSIZE}" ] && {
		fstype=f2fs
		mkfs_arg="-q -l rootfs_data"
	}

	v "Format new rootfs_data at position ${rootfs_data_offset}."
	mkfs.${fstype} ${mkfs_arg} ${loopdev}
	[ $? -ne 0 ] && return 1

	[ -n "$UPGRADE_BACKUP" ] && {
		mkdir -p /tmp/new_root
		mount -t ${fstype} ${loopdev} /tmp/new_root && {
			v "Saving config to rootfs_data at position ${rootfs_data_offset}."
			mv "$UPGRADE_BACKUP" "/tmp/new_root/$BACKUP_FILE"
			umount /tmp/new_root
		}
	}

	# Cleanup
	losetup -d ${loopdev} >/dev/null 2>&1
	sync

	return 0
}

mtk_mmc_do_upgrade_generic() {
	local tar_file="$1"
	local board=$(board_name)
	local kernel_dev=
	local rootfs_dev=
	local cmdline_root="$(mtk_get_root)"

	rootfs_dev=$(block_dev_path "${cmdline_root}")
	[ -z "${rootfs_dev}" -o $? -ne 0 ] && return 1

	case "$board" in
	*)
		kernel_dev=$(blkid -t "PARTLABEL=kernel" -o device)
		[ -z "${kernel_dev}" -o $? -ne 0 ] && return 1
		;;
	esac

	# keep sure its unbound
	losetup --detach-all || {
		v "Failed to detach all loop devices."
		sleep 10
		reboot -f
	}

	mmc_upgrade_tar "${tar_file}" "${kernel_dev}" "${rootfs_dev}"

	[ $? -ne 0 ] && {
		v "Upgrade failed."
		return 1
	}

	return 0
}

mtk_mmc_do_upgrade_dual_boot() {
	local tar_file="$1"
	local kernel_dev=
	local rootfs_dev=
	local rootfs_data_dev=
	local reserve_rootfs_data=$(cat /sys/module/boot_param/parameters/reserve_rootfs_data 2>/dev/null)

	local board_dir=$(tar tf ${tar_file} | grep -m 1 '^sysupgrade-.*/$')
	board_dir=${board_dir%/}

	kernel_dev=$(cat /sys/module/boot_param/parameters/upgrade_kernel_part 2>/dev/null)
	[ -z "${kernel_dev}" -o $? -ne 0 ] && return 1

	kernel_dev=$(block_dev_path "${kernel_dev}")
	[ -z "${kernel_dev}" -o $? -ne 0 ] && return 1

	rootfs_dev=$(cat /sys/module/boot_param/parameters/upgrade_rootfs_part 2>/dev/null)
	[ -z "${rootfs_dev}" -o $? -ne 0 ] && return 1

	rootfs_dev=$(block_dev_path "${rootfs_dev}")
	[ -z "${rootfs_dev}" -o $? -ne 0 ] && return 1

	local kernel_length=$( (tar xf $tar_file ${board_dir}/kernel -O | wc -c) 2> /dev/null)
	local rootfs_length=$( (tar xf $tar_file ${board_dir}/root -O | wc -c) 2> /dev/null)

	[ "${kernel_length}" != 0 ] && {
		tar xf ${tar_file} ${board_dir}/kernel -O >${kernel_dev}
	}

	[ "${rootfs_length}" != 0 ] && {
		tar xf ${tar_file} ${board_dir}/root -O >${rootfs_dev}
	}

	upgrade_image_slot=$(cat /sys/module/boot_param/parameters/upgrade_image_slot 2>/dev/null)
	[ -n "${upgrade_image_slot}" ] && {
		v "Set new boot image slot to ${upgrade_image_slot}"
		# Force the creation of fw_printenv.lock
		mkdir -p /var/lock
		touch /var/lock/fw_printenv.lock
		fw_setenv "dual_boot.current_slot" "${upgrade_image_slot}"
		fw_setenv "dual_boot.slot_${upgrade_image_slot}_invalid" "0"
	}

	if [ x"${reserve_rootfs_data}" = xY ]; then
		# Do not touch rootfs_data
		sync
		return 0
	fi

	rootfs_data_dev=$(cat /sys/module/boot_param/parameters/rootfs_data_part 2>/dev/null)
	[ -z "${rootfs_data_dev}" -o $? -ne 0 ] && return 0

	rootfs_data_dev=$(block_dev_path "${rootfs_data_dev}")
	[ -z "${rootfs_data_dev}" -o $? -ne 0 ] && return 1

	local rootfs_data_dev_size=$(blockdev --getsize64 ${rootfs_data_dev})
	[ $? -ne 0 ] && return 1

	local fstype=ext4
	local mkfs_arg="-q -F -L rootfs_data"
	[ "${rootfs_data_dev_size}" -gt "${F2FS_MINSIZE}" ] && {
		fstype=f2fs
		mkfs_arg="-q -f -l rootfs_data"
	}

	v "Format rootfs_data."
	mkfs.${fstype} ${mkfs_arg} ${rootfs_data_dev}
	[ $? -ne 0 ] && return 1

	[ -n "$UPGRADE_BACKUP" ] && {
		mkdir -p /tmp/new_root
		mount -t ${fstype} ${rootfs_data_dev} /tmp/new_root && {
			v "Saving config to rootfs_data."
			mv "$UPGRADE_BACKUP" "/tmp/new_root/$BACKUP_FILE"
			umount /tmp/new_root
		}
	}

	# Cleanup
	sync

	return 0
}

mtk_mmc_do_upgrade() {
	local dual_boot=$(cat /sys/module/boot_param/parameters/dual_boot 2>/dev/null)

	if [ x"${dual_boot}" = xY ]; then
		mtk_mmc_do_upgrade_dual_boot "$1"
	else
		mtk_mmc_do_upgrade_generic "$1"
	fi

	return $?
}
