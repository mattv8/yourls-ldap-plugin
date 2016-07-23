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
When yourls-ldap-plugin is enabled and user was not successfuly authenticated using data specified in yourls_user_passwords, an LDAP authentication attempt will be made. If LDAP authentication is successful, then you will immediately go to the admin interface.

You can also set a privileged account to search the LDAP directory with. This is useful for directories that don't allow anonymous binding. If you define a suitable template, the current user will be used binding. This is useful for Active Directory / Samba. 

Setting the groups settings will check the user is a member of that group before logging them in and storing their credentials. This check is only performed the first time they auth or when their password changes.

yourls-ldap-plugin by default will now implement a simple cache of LDAP users. As well as reducing requests to the LDAP server this has the effect of allowing YOURLS API to work with LDAP users.

Configuration
-------------

  * define( 'LDAPAUTH_HOST', 'ldaps://ldap.domain.com' ); // LDAP host name, IP or URL. You can use ldaps://host for LDAP with TLS
  * define( 'LDAPAUTH_PORT', '636' ); // LDAP server port - often 389 or 636 for TLS (LDAPS)
  * define( 'LDAPAUTH_BASE', 'dc=domain,dc=com' ); // Base DN (location of users)
  * define( 'LDAPAUTH_USERNAME_FIELD', 'uid'); // (optional) LDAP field name in which username is store

To use a privileged account for the user search:
  * define( 'LDAPAUTH_SEARCH_USER', 'cn=your-user,dc=domain,dc=com' ); // (optional) Privileged user to search with
  * define( 'LDAPAUTH_SEARCH_PASS', 'the-pass'); // (optional) (only if LDAPAUTH_SEARCH_USER set) Privileged user pass

To define a template to bind using the current user for the search: Use %s as the place holder for the current user name
  * define( 'LDAPAUTH_BIND_WITH_USER_TEMPLATE', '%s@myad.domain' ); // (optional) Use %s as the place holder for the current user name

To check group membership before authenticating:
  * define( 'LDAPAUTH_GROUP_ATTR', 'memberof' ); // (optional) LDAP groups attr
  * define( 'LDAPAUTH_GROUP_REQ', 'the-group;another-admin-group'); // (only if LDAPAUTH_GROUP_REQ set) Group/s user must be in. Allows multiple, semicolon delimited

To define the type of user cache used:
  * define( 'LDAPAUTH_USERCACHE_TYPE', 0); // (optional) Defaults to 1, which caches users in the options table. 0 turns off cacheing. Other values are currently undefined, but may be one day

To automatically add LDAP users to config.php:
  * define( 'LDAPAUTH_ADD_NEW', true ); // (optional) Add LDAP users to config.php
NOTE: This will require config.php to be writable by your webserver user. This function is now largely unneeded because the database based cache offers similar benefits without the need to make config.php writeable. It is retained for backwards compatability
 
Troubleshooting
---------------
  * Check PHP error log usually at `/var/log/php.log`
  * Check your webserver logs
  * You can try modifying plugin code to print some more debug info

About the user cache
--------------------
When a successful login is made against an LDAP server the plugin will cache the username and encrypted password. Currently this is done by saving them in an array in the YOURLS options table. This has some advantages:

  * It reduces requests to the LDAP server
  * It means that users can still log in even if the LDAP server is unreachable
  * It means that the YOURLS API can be used by LDAP users

Unfortunately, the cache will not scale well. This is because it integrates tightly with YOURLS's internal auth mechanism, and that does not scale. If you have a few tens of LDAP users likely to use your YOURLS installation it should be fine. Much more than that and you may see performance issues. If so, you should probably disable the cache. This will mean
that your LDAP users will not be able to use the API. At least not unless they are also listed in users/config.php, which suffers from the same scaling problems. 

License
-------
Copyright 2013 K3A, #1davoaust <BR>
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
