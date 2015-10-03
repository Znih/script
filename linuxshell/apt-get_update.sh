#-------------------------------------------------------------------------------
# File:         getupdate.sh
# Date:         15.02.2015
# Description:  Check for software updates and get upgrade res. dist-upgrade (root)
# Maintainer:   Marco Hinz <https://github.com/hinzigers>
# Version:      1.0
#-------------------------------------------------------------------------------
apt-get -y update
apt-get -y upgrade
apt-get -y dist-upgrade
apt-get -y autoremove --purge
