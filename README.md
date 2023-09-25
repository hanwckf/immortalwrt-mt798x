<img src="https://avatars.githubusercontent.com/u/53193414?s=200&v=4" alt="logo" width="200" height="200" align="right">

# Project ImmortalWrt

ImmortalWrt is a fork of [OpenWrt](https://openwrt.org), with more packages ported, more devices supported, better performance, and special optimizations for mainland China users.<br/>
Compared the official one, we allow to use hacks or non-upstreamable patches / modifications to achieve our purpose. Source from anywhere.

Default login address: http://192.168.1.1 or http://immortalwrt.lan, username: __root__, password: _none_.

## About immortalwrt-mt798x 
- https://cmi.hanwckf.top/p/immortalwrt-mt798x/

## Development
To build your own firmware you need a GNU/Linux, BSD or MacOSX system (case sensitive filesystem required). Cygwin is unsupported because of the lack of a case sensitive file system.<br/>

  ### Requirements
  To build with this project, Ubuntu 20.04 LTS is preferred. And you need use the CPU based on AMD64 architecture, with at least 4GB RAM and 25 GB available disk space. Make sure the __Internet__ is accessible.

  The following tools are needed to compile ImmortalWrt, the package names vary between distributions.

  - Here is an example for Ubuntu users:<br/>
    - Method 1:
      <details>
        <summary>Setup dependencies via APT</summary>

        ```bash
        sudo apt update -y
        sudo apt full-upgrade -y
        sudo apt install -y ack antlr3 asciidoc autoconf automake autopoint binutils bison build-essential \
          bzip2 ccache clang clangd cmake cpio curl device-tree-compiler ecj fastjar flex gawk gettext gcc-multilib \
          g++-multilib git gperf haveged help2man intltool lib32gcc-s1 libc6-dev-i386 libelf-dev libglib2.0-dev \
          libgmp3-dev libltdl-dev libmpc-dev libmpfr-dev libncurses5-dev libncursesw5 libncursesw5-dev libreadline-dev \
          libssl-dev libtool lld lldb lrzsz mkisofs msmtp nano ninja-build p7zip p7zip-full patch pkgconf python2.7 \
          python3 python3-pip python3-ply python-docutils qemu-utils re2c rsync scons squashfs-tools subversion swig \
          texinfo uglifyjs upx-ucl unzip vim wget xmlto xxd zlib1g-dev
        ```
      </details>
    - Method 2:
      ```bash
      sudo bash -c 'bash <(curl -s https://build-scripts.immortalwrt.eu.org/init_build_environment.sh)'
      ```

  Note:
  - Do everything as an unprivileged user, not root, without sudo.
  - Using CPUs based on other architectures should be fine to compile ImmortalWrt, but more hacks are needed - No warranty at all.
  - You must __not__ have spaces or non-ascii characters in PATH or in the work folders on the drive.
  - If you're using Windows Subsystem for Linux (or WSL), removing Windows folders from PATH is required, please see [Build system setup WSL](https://openwrt.org/docs/guide-developer/build-system/wsl) documentation.
  - Using macOS as the host build OS is __not__ recommended. No warranty at all. You can get tips from [Build system setup macOS](https://openwrt.org/docs/guide-developer/build-system/buildroot.exigence.macosx) documentation.
  - For more details, please see [Build system setup](https://openwrt.org/docs/guide-developer/build-system/install-buildsystem) documentation.

  ### Quickstart
  1. Run `git clone --depth=1 https://github.com/hanwckf/immortalwrt-mt798x.git` to clone the source code.
  2. Run `cd immortalwrt-mt798x` to enter source directory.
  3. Run `./scripts/feeds update -a` to obtain all the latest package definitions defined in feeds.conf / feeds.conf.default
  4. Run `./scripts/feeds install -a` to install symlinks for all obtained packages into package/feeds/
  5. Run `make menuconfig` to select your preferred configuration for the toolchain, target system & firmware packages.
  6. Run `make` to build your firmware. This will download all sources, build the cross-compile toolchain and then cross-compile the GNU/Linux kernel & all chosen applications for your target system.

  ### Related Repositories
  The main repository uses multiple sub-repositories to manage packages of different categories. All packages are installed via the ImmortalWrt package manager called opkg. If you're looking to develop the web interface or port packages to ImmortalWrt, please find the fitting repository below.
  - [LuCI Web Interface](https://github.com/immortalwrt/luci): Modern and modular interface to control the device via a web browser.
  - [ImmortalWrt Packages](https://github.com/immortalwrt/packages): Community repository of ported packages.
  - [OpenWrt Routing](https://github.com/openwrt/routing): Packages specifically focused on (mesh) routing.

## Support Information
For a list of supported devices see the [OpenWrt Hardware Database](https://openwrt.org/supported_devices)
  ### Documentation
  - [Quick Start Guide](https://openwrt.org/docs/guide-quick-start/start)
  - [User Guide](https://openwrt.org/docs/guide-user/start)
  - [Developer Documentation](https://openwrt.org/docs/guide-developer/start)
  - [Technical Reference](https://openwrt.org/docs/techref/start)

  ### Support Community
  - Support Chat: group [@ctcgfw_openwrt_discuss](https://t.me/ctcgfw_openwrt_discuss) on [Telegram](https://telegram.org/).
  - Support Chat: group [#immortalwrt](https://matrix.to/#/#immortalwrt:matrix.org) on [Matrix](https://matrix.org/).

## License
ImmortalWrt is licensed under [GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html).

## Acknowledgements
<table>
  <tr>
    <td><a href="https://dlercloud.com/"><img src="https://user-images.githubusercontent.com/22235437/111103249-f9ec6e00-8588-11eb-9bfc-67cc55574555.png" width="183" height="52" border="0" alt="Dler Cloud"></a></td>
    <td><a href="https://www.jetbrains.com/"><img src="https://resources.jetbrains.com/storage/products/company/brand/logos/jb_square.png" width="120" height="120" border="0" alt="JetBrains Black Box Logo logo"></a></td>
    <td><a href="https://sourceforge.net/"><img src="https://sourceforge.net/sflogo.php?type=17&group_id=3663829" alt="SourceForge" width=200></a></td>
  </tr>
</table>
