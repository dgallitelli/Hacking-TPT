#!/bin/bash

if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

if [ $1 = 'mysql' ]; then
    echo "Installing mysql ..."
    echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d \
	apt-get install -y debconf-utils \
    echo mysql-server mysql-server/root_password password root | debconf-set-selections \
    echo mysql-server mysql-server/root_password_again password root | debconf-set-selections \
    apt-get install -y mysql-server -o pkg::Options::="--force-confdef" -o pkg::Options::="--force-confold" --fix-missing \
    apt-get install -y mysql-client
fi

echo -n "Installing gcc, golang, electric-fence ..."
apt-get install -y gcc golang electric-fence

echo "Creating folder /etc/xcompile ..."
mkdir /etc/xcompile > /dev/null 2>&1

declare -a compilers=("armv4l" "armv5l" "armv6l" "i586" "m68k" "mips" "mipsel" "powerpc" "sh4" "sparc")

cd /etc/xcompile
echo "downloading cross-compilers ..."
for comp in ${compilers[@]}; do
    if [ ! -f ./cross-compiler-$comp.tar.bz2 ]; then
        wget https://www.uclibc.org/downloads/binaries/0.9.30.1/cross-compiler-$comp.tar.bz2
    fi
done

echo "extracting cross-compilers ..."
for comp in ${compilers[@]}; do
    echo "extracting cross-compiler-$comp.tar.bz2 ..."
    tar -jxf cross-compiler-$comp.tar.bz2
done

echo "removing all tar.bz2 from /etc/xcompile ..."
rm *.tar.bz2

echo "renaming cross-compilers ..."
for comp in ${compilers[@]}; do
    echo "renaming cross-compiler-$comp to $comp ..."
    mv cross-compiler-$comp $comp
done

echo "exporting PATH ..."
for comp in ${compilers[@]}; do
    export PATH=$PATH:/etc/xcompile/$comp/bin
done

echo "### ALL DONE - ENJOY MIRAI ###"
