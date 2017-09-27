apt-get update
apt-get install apache2
apt-get install python-software-properties
apt install php7.0-cli
apt-get install php7.0-dev
apt-get install php7.0-mbstring
apt-get install libapache2-mod-php7.0
phpize
./configure --with-pdo-4d
make
make install
ln -s /usr/include/php/20151012/ /usr/include/php
sh -c "echo extension=pdo_4d.so > /etc/php/7.0/mods-available/pdo_4d.ini"
phpenmod pdo_4d