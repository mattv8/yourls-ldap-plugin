yourls-ldap-plugin
==================

This plugin for [YOURLS](https://github.com/YOURLS/YOURLS) enables the simple use of [LDAP](http://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) for user authentication. 

Installation
------------
1. Download the latest yourls-ldap-plugin.
1. Copy the plugin folder into your user/plugins folder for YOURLS.
1. Set up the parameters for yourls-ldap-plugin in YOURLS configuration user/config.php (see below).
1. Activate the plugin with the plugin manager in the admin interface.

Usage
-----
When yourls-cas-plugin is enabled and user was not successfuly authenticated using data specified in yourls_user_passwords, an LDAP authentication attempt will be made. If LDAP authentication is successful, then you will immediately go to the admin interface.

You can also set a privileged account to search the LDAP directory with. This is useful for directories that don't allow anonymous binding.

Setting the groups settings will check the user is a member of that group before logging them in and storing their credentials. This check is only performed the first time they auth or when their password changes.

Configuration
-------------

  * define( 'LDAPAUTH_HOST', 'ldaps://ldap.domain.com' ) LDAP host name, IP or URL. You can use ldaps://host for LDAP with TLS
  * define( 'LDAPAUTH_PORT', '636' ) LDAP server port - often 389 or 636 for TLS (LDAPS)
  * define( 'LDAPAUTH_BASE', 'dc=domain,dc=com' ) Base DN (location of users)
  * define( 'LDAPAUTH_USERNAME_FIELD', 'uid') (optional) LDAP field name in which username is store

To use a privileged account for the user search:
  * define( 'LDAPAUTH_SEARCH_USER', 'cn=your-user,dc=domain,dc=com' ) // (optional) Privileged user to search with
  * define( 'LDAPAUTH_SEARCH_PASS', 'the-pass') // (optional) (only if LDAPAUTH_SEARCH_USER set) Privileged user pass

To check group membership before authenticating:
  * define( 'LDAPAUTH_GROUP_ATTR', 'memberof' ) // (optional) LDAP groups attr
  * define( 'LDAPAUTH_GROUP_REQ', 'the-group') // (only if LDAPAUTH_GROUP_REQ set) Group user must be in
 
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
