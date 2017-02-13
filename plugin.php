<?php
/*
Plugin Name: Simple LDAP Auth
Plugin URI: 
Description: This plugin enables use of LDAP provider for authentication
Version: 1.0
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


yourls_add_filter( 'is_valid_user', 'ldapauth_is_valid_user' );

// returns true/false
function ldapauth_is_valid_user( $value ) {
	global $yourls_user_passwords;
	global $ydb;

	// Always check & set early
	if ( !ldapauth_environment_check() ) {
		die( 'Invalid configuration for YOURLS LDAP plugin. Check PHP error log.' );
	}

	if( LDAPAUTH_USERCACHE_TYPE == 1) {
		$ldapauth_usercache = $ydb->option['ldapauth_usercache'];
	}
	
	// no point in continuing if the user has already been validated by core
	if ($value) {
		ldapauth_debug("Returning from ldapauth_is_valid_user as user is already validated");
		return $value;
	}
	
	// session is only needed if we don't use usercache
	if (empty(LDAPAUTH_USERCACHE_TYPE)) {
		@session_start();
	}

	if ( empty(LDAPAUTH_USERCACHE_TYPE) && isset( $_SESSION['LDAPAUTH_AUTH_USER'] ) ) {
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
			return $username.' is not admin user.';
		}
	} else if ( isset( $_REQUEST['username'] ) && isset( $_REQUEST['password'] )
			&& !empty( $_REQUEST['username'] ) && !empty( $_REQUEST['password']  ) ) {

		// try to authenticate
		$ldapConnection = ldap_connect(LDAPAUTH_HOST, LDAPAUTH_PORT);
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

		// Limit the attrs to the ones we need
		$attrs = array('dn', LDAPAUTH_USERNAME_FIELD);
		if (defined('LDAPAUTH_GROUP_ATTR'))
			array_push($attrs, LDAPAUTH_GROUP_ATTR);
		
		$searchDn = ldap_search($ldapConnection, LDAPAUTH_BASE, LDAPAUTH_USERNAME_FIELD . "=" . $_REQUEST['username'], $attrs );
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
	
                           $in_group = false;
			   $bind = ldap_bind($ldapConnection, LDAPAUTH_SEARCH_USER, LDAPAUTH_SEARCH_PASS);

			   $groups_to_check = explode(";", strtolower(LDAPAUTH_GROUP_REQ)); // This is now an array
			   foreach($groups_to_check as $group){
		                   $searchGroup = ldap_search($ldapConnection, $group, LDAPAUTH_GROUP_ATTR . "=" . $_REQUEST['username']);
	                           $searchG = ldap_get_entries($ldapConnection,$searchGroup);
				   if ( LDAPAUTH_GROUP_SCOP == 'base'){
					if ($searchG[0]['dn'] == $group) $in_group = true;
					}
				   else{
					if ($searchG[0]['dn']) $in_group = true;
				   }
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
			if (empty(LDAPAUTH_USERCACHE_TYPE)) {
				$_SESSION['LDAPAUTH_AUTH_USER'] = $username;
			}
			return true;
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
	if (empty(LDAPAUTH_USERCACHE_TYPE)) {
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

yourls_add_action ('plugins_loaded', 'ldapauth_merge_users');
function ldapauth_merge_users() {
	global $ydb;
	global $yourls_user_passwords;
	if ( !ldapauth_environment_check() ) {
		die( 'Invalid configuration for YOURLS LDAP plugin. Check PHP error log.' );
	}
	if(LDAPAUTH_USERCACHE_TYPE==1 && isset($ydb->option['ldapauth_usercache'])) {
		ldapauth_debug("Merging text file users and cached LDAP users");
		$yourls_user_passwords = array_merge($yourls_user_passwords, $ydb->option['ldapauth_usercache']);
	}
}
/**
 * Create user in config file
 * Code reused from yourls_hash_passwords_now()
 */
function ldapauth_create_user( $user, $new_password ) {
	$configdata = file_get_contents( YOURLS_CONFIGFILE );
	if ( $configdata == FALSE )	{
		die('Couldn\'t read the config file');
	}
	
	if (!is_writable(YOURLS_CONFIGFILE))
		die('Can\'t write to config file');
		
	$pass_hash = ldapauth_hash_password($new_password);
	$user_line = "\t'$user' => 'phpass:$pass_hash' /* Password encrypted by YOURLS */,";
	
	// Add the user on a new line after the start of the passwords array
	$new_contents = preg_replace('/(yourls_user_passwords\s=\sarray\()/',  '$0 ' . PHP_EOL . $user_line, $configdata, -1, $count);
	
	if ($count === 0) {
		die('Couldn\'t add user, plugin may not be compatible with YourLS version');
	} else if ($count > 1) {
		die('Added user more than once. Check config file.');
	}
		
	$success = file_put_contents( YOURLS_CONFIGFILE, $new_contents );
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
