yourls-ldap-plugin
==================

This plugin for [YOURLS](https://github.com/YOURLS/YOURLS) enables the simple use of [LDAP](http://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) for user authentication. 

Installation
------------
1. Download the latest yourls-ldap-plugin.
1. Copy the plugin folder into your user/plugins folder for YOURLS.
1. Set up the parameters for yourls-ldap-plugin in YOURLS configuration (see below).
1. Activate the plugin with the plugin manager in the admin interface.

Usage
-----
When yourls-cas-plugin is enabled and user was not successfuly authenticated using data specified in yourls_user_passwords, an LDAP authentication attempt will be made. If LDAP authentication is successful, then you will immediately go to the admin interface.

Configuration
-------------
  * `LDAP_HOST` LDAP host name, IP or URL. You can use ldaps://host for LDAP with TLS
  * `LDAP_PORT` LDAP server port - often 389 or 636 for TLS (LDAPS)
  * `LDAP_BASE` Base DN (location of users)
  * `LDAP_USERNAME_FIELD` (optional) LDAP field name in which username is store

Troubleshooting
---------------
  * Check PHP error log usually at `/var/log/php.log`
  * Check your webserver logs
  * You can try modifying plugin code to print some more debug info

License
-------
Copyright 2013 K3A <BR>
Copyright 2013 Nicholas Waller (code@nicwaller.com) as I used some parts of his CAS authentication plugin :)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
