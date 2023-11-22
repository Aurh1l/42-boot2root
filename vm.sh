#!/usr/bin/env bash

set -euo pipefail

host_ssh_port=22

iso_url="https://cdn.intra.42.fr/isos/BornToSecHackMe-v1.1.iso"

[ -d "$HOME/goinfre" ] && vm_dir="$HOME/goinfre" || vm_dir="$PWD"

vm_os="Linux_64"
vm_image="$vm_dir/$(basename "$iso_url")"
vm_name="Boot2Root"
vm_ram="1024"
vm_vram="0"
vm_gfx="none"
vm_net="hostonly" # hostonly bridged
vm_bridge_adapter="en0"
vm_hostonly_adapter="vboxnet0"

vm_ssh_port=22

print_help()
{
	echo -e "Usage $0 [command]
Commands:
    up      Setup and stat the virtual machine.
    down    Unregister and delete the virtual machine.
    ip      Show a running virtual machine's IPV4 address.
    ssh     Connect to the virtual machine using SSH.
    help    Show this help message.

If no argument is provided, 'up' will be assumed."
}

print_ssh_usage() # progname
{
	local progname="${1:-ssh}"

	echo -e "Usage: $0 $progname user[:pass]"
}

print_scp_usage() #progname
{
	local progname="${1:-scp}"

	echo -e "Usage: $0 $progname user[:pass] source ... target\n\nLocations on the vm should be prefixed with a colon character (':')."
}
print_vm_stopped()
{
	echo -e "'$vm_name' is not running!

Use '$0 up' to start it up."
}

print_vm_started()
{
	echo -e "'$vm_name' was already started!

Use '$0 ssh' to connect."
}

vm_exists()
{
	VBoxManage showvminfo "$vm_name" > /dev/null 2>&1
}

vm_running()
{
	VBoxManage list runningvms | grep "\"$vm_name\"" > /dev/null
}

vm_checkif()
{
	local ifname="$1"

	echo "Checking for interface $ifname..." >&2

	ifconfig "$ifname" >/dev/null 2>&1
}

vm_net_hostonly_up()
{
	local ifname="$vm_hostonly_adapter"

	vm_checkif "$ifname" || VBoxManage hostonlyif create
	VBoxManage modifyvm "$vm_name" --hostonlyadapter1 "$ifname"
}

vm_net_bridged_up()
{
	VBoxManage modifyvm "$vm_name" --bridgeadapter1 "$vm_bridge_adapter"
}

vm_net_nat_up()
{
	VBoxManage modifyvm "$vm_name" --natpf1 "ssh,tcp,,$host_ssh_port,,$vm_ssh_port"
}

vm_up()
{
	local src_dir="$PWD"
	if ! vm_exists
	then
		# Download the disk image.
		pushd "$(dirname "$vm_image")"
			while ! md5sum --check "$src_dir/md5sums"
			do
				echo "Fetching '$vm_image'..."

				curl -L -O -C - "$iso_url" --output "$vm_image"
			done
		popd

		echo "Initializing '$vm_name' at '$vm_dir'..."

		# Create and register vm in current working directory.
		VBoxManage createvm --name "$vm_name" --ostype "$vm_os" --register --basefolder "$vm_dir"
		VBoxManage modifyvm "$vm_name" --memory "$vm_ram" --vram "$vm_vram" --graphicscontroller "$vm_gfx" --nic1 "$vm_net"

		case "$vm_net" in
			"hostonly"	)	vm_net_hostonly_up;;
			"bridged"	)	vm_net_bridged_up;;
			"nat"		)	vm_net_nat_up;;
		esac

		# Add an IDE controller
		VBoxManage storagectl "$vm_name" --name "IDE Controller" --add ide --controller PIIX4

		# Attach the disk image.
		VBoxManage storageattach "$vm_name" --storagectl "IDE Controller" --port 0 --device 0 --type dvddrive --medium "$vm_image"
	fi

	if ! vm_running
	then
		echo "Starting '$vm_name'..."
		VBoxManage startvm "$vm_name" --type headless
	else
		print_vm_started >&2
		return 1
	fi
}

vm_down()
{
	if vm_exists
	then
		if vm_running
		then
			echo "Waiting for '$vm_name' to power off..."
			VBoxManage controlvm "$vm_name" poweroff && sleep 2
		fi
		echo "Tearing down '$vm_name'..."
		VBoxManage unregistervm "$vm_name" --delete
	fi
}

vm_mac()
{
	VBoxManage showvminfo Boot2Root --machinereadable \
	| grep -m1 'macaddress[[:digit:]]\+' \
	| cut -d '=' -f 2- \
	| tr -d '"'
}

vm_ipv4_hostonly()
{
	local mac_address

	mac_address=$(vm_mac)

	VBoxManage dhcpserver findlease \
		--interface="$vm_hostonly_adapter" --mac-address="$mac_address" \
	| grep IP -m1 | cut -d ':' -f2- | tr -d ' '
}

vm_ipv4_bridged()
{
	VBoxManage guestproperty get "$vm_name" /VirtualBox/GuestInfo/Net/0/V4/IP \
	| cut -d' ' -f2
}

vm_ipv4()
{
	if vm_running
	then
		case "$vm_net" in
			"hostonly"	)	vm_ipv4_hostonly;;
			"bridged"	)	vm_ipv4_bridged;;
			"nat"		)	echo "localhost";;
			"*"			)	echo "The '$vm_net' network mode is not supported!" >&2; return 1;;
		esac
	else
		print_vm_stopped >&2
		return 1
	fi
}

vm_ssh_port()
{
	local port

	if [ "$vm_net" = nat ]
	then
		port="$host_ssh_port"
	else
		port="$vm_ssh_port"
	fi

	echo "$port"
}

vm_pass() # pass cmd
{
	local pass="${1:-}"; shift
	local cmd=("${@}")

	if vm_running
	then
		# Set TERM=xterm if using alacritty or termite
		[ "$TERM" = alacritty ] || [ "$TERM" = "xterm-termite" ] && TERM=xterm

		if [ -n "$pass" ]
		then
			"$(dirname "$0")/utils/pass.exp" "$pass" "${cmd[@]}"
		else
			"${cmd[@]}"
		fi
	else
		print_vm_stopped >&2
		return 1
	fi
}

vm_ssh() # user
{
	local user="${1:-}"; shift

	local pass host port

	if [ -z "$user" ]
	then
		echo "$0: ssh: Missing user argument." >&2
		print_ssh_usage ssh >&2
		return 1
	fi

	pass="${user##*:}"
	host=$(vm_ipv4)
	port=$(vm_ssh_port)

	vm_pass "$pass" ssh -o "UserKnownHostsFile=/dev/null" -p "$port" "$@" "${user%%:*}@$(vm_ipv4)"
}

vm_scp() # user source ... target
{
	local user="${1:-}"; shift

	local pass host port files file

	if [ -z "$user" ]
	then
		echo "$0: scp: Missing user argument." >&2
		print_ssh_usage scp >&2
		return 1
	fi

	files=("$@")

	if [ ${#files[@]} -lt 2 ]
	then
		echo "$0: scp: Missing source and/or target argument." >&2
		print_scp_usage scp >&2
		return 1
	fi

	pass="${user##*:}"
	host=$(vm_ipv4)
	port=$(vm_ssh_port)

	for (( i=0; i<$#; ++i ))
	do
		file="${files[i]}"

		[ "${file:0:1}" = : ] && files[i]="${user%%:*}@$host:${file:1}"
	done

	vm_pass "$pass" scp -o "UserKnownHostsFile=/dev/null" -P "$port" "${files[@]}"
}

case "${1:-}" in
	"up" | ""	)	vm_up;;
	"down"		)	vm_down;;
	"ip"		)	vm_ipv4;;
	"ssh"		)	shift; vm_ssh "$@";;
	"scp"		)	shift; vm_scp "$@";;
	"help"		)	print_help;;
	*			)	print_help && exit 1;;
esac
