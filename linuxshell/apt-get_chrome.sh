#-------------------------------------------------------------------------------
# File:         apt-update.sh
# Date:         15.02.2015
# Description:  install google chrome browser (root)
# Maintainer:   Marco Hinz <https://github.com/hinzigers>
# Version:      1.0
#-------------------------------------------------------------------------------
sh -c 'echo "deb http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list'
wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add -
apt-get -y update
apt-get -y install google-chrome-stable
