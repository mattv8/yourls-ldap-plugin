<?php
/*
Plugin Name: Simple LDAP Auth
Plugin URI: 
Description: This plugin enables use of LDAP provider for authentication
Version: 1.1
Author: k3a
Author URI: http://k3a.me
*/
// Thanks to nicwaller (https://github.com/nicwaller) for cas plugin I used as a reference!

// No direct call
if( !defined( 'YOURLS_ABSPATH' ) ) die();


// returns true if the environment is set up right
function ldapauth_environment_check() {
	$required_params = array(
		'LDAPAUTH_HOST', // ldap host
		//'LDAPAUTH_PORT', // ldap port
		'LDAPAUTH_BASE', // base ldap path
		//'LDAPAUTH_USERNAME_FIELD', // field to check the username against
	);

	foreach ($required_params as $pname) {
		if ( !defined( $pname ) ) {
			$message = 'Missing defined parameter '.$pname.' in plugin '. $thisplugname;
			error_log($message);
			return false;
		}
	}

	if ( !defined( 'LDAPAUTH_PORT' ) )
		define( 'LDAPAUTH_PORT', 389 );

	if ( !defined( 'LDAPAUTH_USERNAME_FIELD' ) )
		define( 'LDAPAUTH_USERNAME_FIELD', 'uid' );

	if ( !defined( 'LDAPAUTH_ALL_USERS_ADMIN' ) )
		define( 'LDAPAUTH_ALL_USERS_ADMIN', true );

	if ( !defined( 'LDAPAUTH_ADD_NEW' ) )
		define( 'LDAPAUTH_ADD_NEW', false );

	if ( !defined( 'LDAPAUTH_USERCACHE_TYPE' ) )
		define( 'LDAPAUTH_USERCACHE_TYPE', 1 );
		
	global $ldapauth_authorized_admins;
	if ( !isset( $ldapauth_authorized_admins ) ) {
		if ( !LDAPAUTH_ALL_USERS_ADMIN ) {
			error_log('Undefined $ldapauth_authorized_admins');
		}
		$ldapauth_authorized_admins = array();
	}

	return true;
}

# Reroute login to yourls filter 
# (see https://github.com/YOURLS/YOURLS/wiki/Advanced-Hook-Syntax)
//yourls_add_filter( 'is_valid_user', 'ldapauth_is_valid_user' );
yourls_add_filter( 'shunt_is_valid_user', 'ldapauth_is_valid_user' );

function ldapauth_shuffle_assoc($list) {
	if (!is_array($list)) return $list;

	$keys = array_keys($list);
	shuffle($keys);
	$random = array();
	foreach ($keys as $key) {
		$random[$key] = $list[$key];
	}
	return $random;
}

// return list of Active Directory Ldap servers that are associated with a site and service
// example for $site =  = '_ldap._tcp.corporate._sites.company.com'
function ldapauth_get_ad_servers_for_site() {
	$results = [];
	$ad_servers = dns_get_record(LDAPAUTH_DNS_SITES_AND_SERVICES, DNS_SRV, $authns, $addtl);
	foreach ($ad_servers as $ad_server) {
		array_push($results, $ad_server['target']);
	}
	$results = ldapauth_shuffle_assoc($results);  #randomize the order
	return $results;
}

// returns ldap connection
function ldapauth_get_ldap_connection() {
	if (defined('LDAPAUTH_DNS_SITES_AND_SERVICES')) {
		$connection = NULL;
		$ldap_servers = ldapauth_get_ad_servers_for_site();
		foreach ($ldap_servers as $ldap_server) {
			$ldap_address = LDAPAUTH_HOST . $ldap_server;
			try {
				$temp_conn = ldap_connect($ldap_address, LDAPAUTH_PORT);  # ldap_connect doesn't actually connect it just checks for plausiable parameters.  Only ldap_bind connects
				if ($temp_conn) {
					$connection = $temp_conn;
					break;
				} else {
					error_log('Warning, unable to connect to: ' . $ldap_address . ' on port ' . LDAPAUTH_PORT .  '.  ' . ldap_error($temp_conn));
				}
			} catch (Exception $e) {
				error_log('Warning, unable to connect to: ' . $ldap_address . ' on port ' . LDAPAUTH_PORT . '.	' . __FILE__, __FUNCTION__,$e->getMessage());
			}
		}

		if ($connection) {
			return $connection;
		} else {
			die("Cannot connect to LDAP for site and service " . LDAPAUTH_DNS_SITES_AND_SERVICES);
		}

	} else {
		return ldap_connect(LDAPAUTH_HOST, LDAPAUTH_PORT);
	}
}

// returns true/false
function ldapauth_is_valid_user( $value ) {
	global $yourls_user_passwords;
	
	// Always check & set early
	if ( !ldapauth_environment_check() ) {
		die( 'Invalid configuration for YOURLS LDAP plugin. Check PHP error log.' );
	}

	if( LDAPAUTH_USERCACHE_TYPE == 1) {
		$ldapauth_usercache = yourls_get_option('ldapauth_usercache');
	}
	
	// no point in continuing if the user has already been validated by core
	if ($value) {
		ldapauth_debug("Returning from ldapauth_is_valid_user as user is already validated");
		return $value;
	}
	
	// session is only needed if we don't use usercache
	if (!defined(LDAPAUTH_USERCACHE_TYPE)) {
		@session_start();
	}

	if (!defined(LDAPAUTH_USERCACHE_TYPE) && isset( $_SESSION['LDAPAUTH_AUTH_USER'] ) ) {
		// already authenticated...
		$username = $_SESSION['LDAPAUTH_AUTH_USER'];

		// why is this checked here, but not before the cookie is set?
		if ( ldapauth_is_authorized_user( $username ) ) { 
			if( !isset($yourls_user_passwords[$username]) ) {
				// set a dummy password to work around the "Stealing cookies" problem
				// we prepend with 'phpass:' to avoid YOURLS trying to auto-encrypt it and
				// write it to user/config.php
				ldapauth_debug('Setting dummy entry in $yourls_user_passwords for user ' . $username);
				$yourls_user_passwords[$username]='phpass:ThereIsNoPasswordButHey,WhoCares?';
			}
			yourls_set_user( $_SESSION['LDAPAUTH_AUTH_USER'] );
			return true;
		} else {
			ldapauth_debug($username . ' is not admin user.');
			return $value;
		}
	} else if ( isset( $_REQUEST['username'] ) && isset( $_REQUEST['password'] )
			&& !empty( $_REQUEST['username'] ) && !empty( $_REQUEST['password']  ) ) {

		// try to authenticate
		$ldapConnection = ldapauth_get_ldap_connection();
		if (!$ldapConnection) die("Cannot connect to LDAP " . LDAPAUTH_HOST);
		ldap_set_option($ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3);
		//ldap_set_option($ldapConnection, LDAP_OPT_REFERRALS, 0);
		
		// should we to try and bind using the credentials being logged in with?
		if (defined('LDAPAUTH_BIND_WITH_USER_TEMPLATE')) {
			$bindRDN = sprintf(LDAPAUTH_BIND_WITH_USER_TEMPLATE, $_REQUEST['username']);
			if (!($ldapSuccess = @ldap_bind($ldapConnection, $bindRDN, $_REQUEST['password']))) {
				error_log('Couldn\'t bind to LDAP server with user ' . $bindRDN);
				return $value;
			}
		} 
		
		// Check if using a privileged user account to search - only if not already bound with current user
		if (defined('LDAPAUTH_SEARCH_USER') && defined('LDAPAUTH_SEARCH_PASS') && empty($ldapSuccess)) {
			if (!@ldap_bind($ldapConnection, LDAPAUTH_SEARCH_USER, LDAPAUTH_SEARCH_PASS)) {
				die('Couldn\'t bind search user ' . LDAPAUTH_SEARCH_USER);
			}
		}

		// Check if using LDAP Filter, otherwise, filter by LDAPAUTH_USERNAME_FIELD only.
		if ( !defined('LDAPAUTH_SEARCH_FILTER') ){
			$ldapFilter = LDAPAUTH_USERNAME_FIELD . "=" . $_REQUEST['username'];
		} else {
			$ldapFilter = sprintf(LDAPAUTH_SEARCH_FILTER, $_REQUEST['username']);
		}

		// Limit the attrs to the ones we need
		$attrs = array('dn', LDAPAUTH_USERNAME_FIELD);
		if (defined('LDAPAUTH_GROUP_ATTR'))
			array_push($attrs, LDAPAUTH_GROUP_ATTR);
		
		$searchDn = ldap_search($ldapConnection, LDAPAUTH_BASE, $ldapFilter, $attrs );
		if (!$searchDn) return $value;
		$searchResult = ldap_get_entries($ldapConnection, $searchDn);
		if (!$searchResult) return $value;
		$userDn = $searchResult[0]['dn'];
		if (!$userDn && !$ldapSuccess) return $value;	
		if (empty($ldapSuccess)) { // we don't need to do this if we already bound using username and LDAPAUTH_BIND_WITH_USER_TEMPLATE
			$ldapSuccess = @ldap_bind($ldapConnection, $userDn, $_REQUEST['password']);
		}

		// success?
		if ($ldapSuccess)
		{
			// are we checking group auth?
			if (defined('LDAPAUTH_GROUP_ATTR') && defined('LDAPAUTH_GROUP_REQ')) {
				if (!array_key_exists(LDAPAUTH_GROUP_ATTR, $searchResult[0])) die('Not in any LDAP groups');
				
				$in_group = false;
				$groups_to_check = explode(";", strtolower(LDAPAUTH_GROUP_REQ)); // This is now an array
				
				foreach($searchResult[0][LDAPAUTH_GROUP_ATTR] as $grps) {
					if (in_array(strtolower($grps), $groups_to_check)) { $in_group = true; break;  }
				}
			
				if (!$in_group) die('Not in admin group');
			}
			
			// attribute index returned by ldap_get_entries is lowercased (http://php.net/manual/en/function.ldap-get-entries.php)
			$username = $searchResult[0][strtolower(LDAPAUTH_USERNAME_FIELD)][0];
			yourls_set_user($username);
			
			if (LDAPAUTH_ADD_NEW && !array_key_exists($username, $yourls_user_passwords)) {
				ldapauth_create_user( $username, $_REQUEST['password'] );
			}
			
			if (LDAPAUTH_USERCACHE_TYPE == 1) {
				// store the current user credentials in our cache. This cuts down calls to the LDAP 
				// server, and allows API keys to work with LDAP users
				$ldapauth_usercache[$username] = 'phpass:' . ldapauth_hash_password($_REQUEST['password']);
				yourls_update_option('ldapauth_usercache', $ldapauth_usercache);
			}

			$yourls_user_passwords[$username] = ldapauth_hash_password($_REQUEST['password']);
			if (!defined(LDAPAUTH_USERCACHE_TYPE)) {
				$_SESSION['LDAPAUTH_AUTH_USER'] = $username;
			}
			return true;
			ldapauth_debug("User $username was successfully authenticated");
		} else {
			error_log("No LDAP success");
		}
	}

	return $value;
}

function ldapauth_is_authorized_user( $username ) {	
	// by default, anybody who can authenticate is also
	// authorized as an administrator.
	if ( LDAPAUTH_ALL_USERS_ADMIN ) {
		return true;
	}

	// users listed in config.php are admin users. let them in.
	global $ldapauth_authorized_admins;
	if ( in_array( $username, $ldapauth_authorized_admins ) ) {
		return true;
	} 
	
	// not an admin user
	return false;
}

yourls_add_action( 'logout', 'ldapauth_logout_hook' );

function ldapauth_logout_hook( $args ) {
	if (!defined(LDAPAUTH_USERCACHE_TYPE)) {
		unset($_SESSION['LDAPAUTH_AUTH_USER']);
		setcookie('PHPSESSID', '', 0, '/');
	}
}

/* This action, called as early as possible, retrieves our cache of LDAP users and 
 * merges it with $yourls_user_passwords. This enables core to do the authorisation
 * of previously seen LDAP users, and also means that API signatures for LDAP users 
 * will work. Users that exist in both users/config.php and LDAP will need to use 
 * their LDAP passwords
 */

yourls_add_action('plugins_loaded', 'ldapauth_merge_users');
function ldapauth_merge_users() {
	global $yourls_user_passwords;
	if ( !ldapauth_environment_check() ) {
		die( 'Invalid configuration for YOURLS LDAP plugin. Check PHP error log.' );
	}
	if(LDAPAUTH_USERCACHE_TYPE==1 && false !== yourls_get_option('ldapauth_usercache')) {
		ldapauth_debug("Merging text file users and cached LDAP users");
		//print_r($yourls_user_passwords) . "<br>";
		$yourls_user_passwords = array_merge($yourls_user_passwords, yourls_get_option('ldapauth_usercache'));
		//print_r($yourls_user_passwords) . "<br>";
		//die('Paused');
	}
}
/**
 * Create user in config file
 * Code reused from yourls_hash_passwords_now()
 */
function ldapauth_create_user( $user, $new_password ) {
	$configdata = htmlspecialchars(file_get_contents( YOURLS_CONFIGFILE ));
	if ( $configdata == FALSE )	{
		die('Couldn\'t read the config file');
	}
	
	if (!is_writable(YOURLS_CONFIGFILE))
		die('Can\'t write to config file');
		
	$pass_hash = ldapauth_hash_password($new_password);
	$user_line = "\t'$user' => 'phpass:$pass_hash' /* LDAP user added by plugin */,";
	
	// Add the user on a new line after the start of the passwords array
	$new_contents = preg_replace('/\$yourls_user_passwords\s=\s\[/',  '$0 ' . PHP_EOL . $user_line, $configdata, -1, $count);
	//echo YOURLS_CONFIGFILE . "<br>";
	//echo $configdata . "<br>";
	//echo $user_line . "<br>";
	//echo $user . "<br>";
	//echo htmlspecialchars_decode($new_contents) . "<br>";
	//echo $count . "<br>";
	//die('Paused');
	
	if ($count === 0) {
		die('Couldn\'t add user, plugin may not be compatible with YourLS version');
	} else if ($count > 1) {
		die('Added user more than once. Check config file.');
	}
		
	$success = file_put_contents( YOURLS_CONFIGFILE, htmlspecialchars_decode($new_contents) );
	if ( $success === false ) {
		die('Unable to save config file');
	}
	
	return $pass_hash;
}
/**
 * Hashes password the same way as yourls_hash_passwords_now()
 **/
function ldapauth_hash_password ($password) {
	$pass_hash = yourls_phpass_hash( $password );
	// PHP would interpret $ as a variable, so replace it in storage.
	$pass_hash = str_replace( '$', '!', $pass_hash );
	
	return $pass_hash;
}
function ldapauth_debug ($msg) {
	if (defined('LDAPAUTH_DEBUG') && LDAPAUTH_DEBUG) { 
		error_log("yourls_ldap_auth: " . $msg);
	}
}



