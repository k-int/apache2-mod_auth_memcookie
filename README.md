apache2-mod_auth_memcookie
==========================

The starting point for this version of this module was the mergeing of https://github.com/richp10/apache2-mod_auth_memcookie-1.0.3 and https://github.com/raghu600/apache2-mod_auth_memcookie

This module makes for a simple way of authorising users by use of memcached (full details can be seen in the readme.html).
The user id, group and the users IP is part of the information stored which is then used to authorise the users,
other information can be stored but is not used as part of the authorisation process

To get going on ubuntu you will need the following packages in order to build it

apt-get install make
apt-get install apache2-dev
apt-get install libmemcached-dev

Then do the following as root and it will install the module into /usr/lib/apache2/modules

make clean all install

For full details see readme.html, I will migrate it to here at some point.

