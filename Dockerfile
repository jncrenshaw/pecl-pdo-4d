FROM php:8.2-apache

# Apt
RUN apt-get update
RUN apt-get install -y libtool
RUN apt-get install -y imagemagick
RUN apt-get install -y git

# Extensions
RUN docker-php-ext-install opcache

# Build our extension
RUN mkdir /var/test
RUN git clone https://github.com/jncrenshaw/pecl-pdo-4d.git /var/test/pecl-pdo-4d
WORKDIR /var/test/pecl-pdo-4d
RUN phpize
RUN ./configure --with-pdo-4d
# RUN make
# RUN install

# Append our extension to the ini
# RUN echo "extension=pdo_4d.so" >> "$PHP_INI_DIR/php.ini"

# RUN docker-php-ext-install .
# 
# 	# software-properties-common \
# 	# php8.2-cli \
# 	# php8.2-mbstring \
# 	# php8.2-imagick \
# 	# php8.2-mysql \
# 	# libapache2-mod-php8.2
# USER root
# WORKDIR /home/root
# RUN mkdir pdo_4d
# WORKDIR /home/root/pdo_4d 
RUN php -m

