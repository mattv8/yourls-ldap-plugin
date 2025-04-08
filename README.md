yourls-ldap-plugin
==================

This plugin for [YOURLS](https://github.com/YOURLS/YOURLS) enables the simple use of [LDAP](http://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol) for user authentication.

Installation
------------
1. Download the latest yourls-ldap-plugin.
2. Copy the plugin folder into your user/plugins folder for YOURLS.
3. Set up the parameters for yourls-ldap-plugin in YOURLS configuration user/config.php (see below).
4. Activate the plugin with the plugin manager in the admin interface.

Usage
-----
When yourls-ldap-plugin is enabled and a user was not successfully authenticated using data specified in yourls_user_passwords, an LDAP authentication attempt will be made. If LDAP authentication is successful, then you will immediately go to the admin interface.

You can also set a privileged account to search the LDAP directory with. This is useful for directories that don't allow anonymous binding. If you define a suitable template, the current user will be used for binding. This is useful for Active Directory / Samba.

Setting the groups settings will check if the user is a member of that group before logging them in and storing their credentials. This check is only performed the first time they authenticate or when their password changes.

yourls-ldap-plugin, by default, will now implement a simple cache of LDAP users. As well as reducing requests to the LDAP server, this has the effect of allowing the YOURLS API to work with LDAP users.

Configuration
-------------

  * define( 'LDAPAUTH_HOST', 'ldaps://ldap.domain.com' ); // LDAP host name, IP, or URL. You can use ldaps://host for LDAP with TLS
  * define( 'LDAPAUTH_PORT', '636' ); // LDAP server port - often 389 or 636 for TLS (LDAPS)
  * define( 'LDAPAUTH_BASE', 'dc=domain,dc=com' ); // Base DN (location of users)
  * define( 'LDAPAUTH_USERNAME_FIELD', 'uid'); // (optional) LDAP field name in which the username is stored

### To use a privileged account for the user search:
  * define( 'LDAPAUTH_SEARCH_USER', 'cn=your-user,dc=domain,dc=com' ); // (optional) Privileged user to search with
  * define( 'LDAPAUTH_SEARCH_PASS', 'the-pass'); // (optional) (only if LDAPAUTH_SEARCH_USER set) Privileged user pass

### To define a template to bind using the current user for the search: Use %s as the placeholder for the current username
  * define( 'LDAPAUTH_BIND_WITH_USER_TEMPLATE', '%s@myad.domain' ); // (optional) Use %s as the placeholder for the current username

### To use a custom LDAP search filter:
  * define( 'LDAPAUTH_SEARCH_FILTER', '(&(samaccountname=%s)(memberof=YOURLS-ADMINS,OU=Groups,DC=example,DC=com))' ); // Use %s as the placeholder for the current username

If this option is not set, the filter is based only on LDAPAUTH_USERNAME_FIELD (default).
This is useful if a more advanced filter is needed, like when using AD nested groups.
For searching based on AD Nested group `LDAP_MATCHING_RULE_IN_CHAIN` OID (1.2.840.113556.1.4.1941) must be specified for the user's memberof attribute.
Example of a filter based on AD nested group:
`define( 'LDAPAUTH_SEARCH_FILTER', '(&(samaccountname=%s)(memberof:1.2.840.113556.1.4.1941:=YOURLS-ADMINS,OU=Groups,DC=example,DC=com))' );`

### To check group membership before authenticating:
  * define( 'LDAPAUTH_GROUP_ATTR', 'memberof' ); // (optional) LDAP groups attribute
  * define( 'LDAPAUTH_GROUP_REQ', 'the-group;another-admin-group'); // (only if LDAPAUTH_GROUP_REQ set) Group/s the user must be in. Allows multiple, semicolon-delimited

### To define the scope of group req search:
  * define( 'LDAPAUTH_GROUP_SCOP', 'sub' ); // if not defined the default is 'sub', and will check for the user in all the subtree. The other option is 'base', which will search only members of the exact req

### To define the type of user cache used:
  * define( 'LDAPAUTH_USERCACHE_TYPE', 0); // (optional) Defaults to 1, which caches users in the options table. 0 turns off caching. Other values are currently undefined but may be one day

### To automatically add LDAP users to config.php:
  * define( 'LDAPAUTH_ADD_NEW', true ); // (optional) Add LDAP users to config.php

### To use Active Directory Sites and Services DNS entry for LDAP server name lookup
  * define( 'LDAPAUTH_DNS_SITES_AND_SERVICES', '_ldap._tcp.corporate._sites.yourdomain.com' ); // If using Active Directory with multiple Domain Controllers, the safe way to use DNS to look up your active LDAP server names.  If set, it will be used to override the hostname portion of LDAPAUTH_HOST.
  * define( 'LDAPAUTH_HOST', 'ldap://'); // LDAP protocol without the hostname. You can use 'ldaps://' for LDAP with TLS.

### To prevent following LDAP referrals
  * define( 'LDAPAUTH_LDAP_OPT_REFERRALS', 0 ); // (optional) Defaults to 1.  When using Active Directory, following LDAP referrals can fail.  It will fail in a way that causes the ldap_search function to hang for at least a minute.  Related [issue](https://github.com/MISP/MISP/issues/2749).

NOTE: This will require config.php to be writable by your webserver user. This function is now largely unneeded because the database-based cache offers similar benefits without the need to make config.php writable. It is retained for backward compatibility.

Troubleshooting
---------------
  * Check the PHP error log usually at `/var/log/php.log`
  * Check your web server logs
  * You can try modifying the plugin code to print some more debug info

About the user cache
--------------------
When a successful login is made against an LDAP server, the plugin will cache the username and encrypted password. Currently, this is done by saving them in an array in the YOURLS options table. This has some advantages:

  * It reduces requests to the LDAP server
  * It means that users can still log in even if the LDAP server is unreachable
  * It means that the YOURLS API can be used by LDAP users

Unfortunately, the cache will not scale well. This is because it integrates tightly with YOURLS's internal auth mechanism, and that does not scale. If you have a few tens of LDAP users likely to use your YOURLS installation, it should be fine. Much more than that, and you may see performance issues. If so, you should probably disable the cache. This will mean that your LDAP users will not be able to use the API. At least not unless they are also listed in users/config.php, which suffers from the same scaling problems.

License
-------
Original Plugin Author(s):<br>
Copyright 2013 K3A, #1davoaust<br>
Copyright 2013 Nicholas Waller (code@nicwaller.com) as I used some parts of his CAS authentication plugin :)

Maintainer(s):<br>
Matt Visnovsky #mattv8<br>

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
