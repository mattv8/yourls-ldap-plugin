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
function ldap_environment_check() {
	$required_params = array(
		'LDAP_HOST', // ldap host
		//'LDAP_PORT', // ldap port
		'LDAP_BASE', // base ldap path
		//'LDAP_USERNAME_FIELD', // field to check the username against
	);

	foreach ($required_params as $pname) {
		if ( !defined( $pname ) ) {
			$message = 'Missing defined parameter '.$pname.' in plugin '. $thisplugname;
			error_log($message);
			return false;
		}
	}

	if ( !defined( 'LDAP_PORT' ) )
		define( 'LDAP_PORT', 389 );

	if ( !defined( 'LDAP_USERNAME_FIELD' ) )
		define( 'LDAP_USERNAME_FIELD', 'uid' );

	if ( !defined( 'LDAP_ALL_USERS_ADMIN' ) )
		define( 'LDAP_ALL_USERS_ADMIN', true );

	global $ldap_authorized_admins;
	if ( !isset( $ldap_authorized_admins ) ) {
		if ( !LDAP_ALL_USERS_ADMIN ) {
			error_log('Undefined $ldap_authorized_admins');
		}
		$ldap_authorized_admins = array();
	}

	return true;
}


yourls_add_filter( 'is_valid_user', 'ldap_is_valid_user' );

// returns true/false
function ldap_is_valid_user( $value ) {
	// doesn't work for API...
	if (yourls_is_API())
		return $value;

	@session_start();

	if ( isset( $_SESSION['LDAP_AUTH_USER'] ) ) {
		// already authenticated...
		$username = $_SESSION['LDAP_AUTH_USER'];
		if ( ldap_is_authorized_user( $username ) ) {
			yourls_set_user( $_SESSION['LDAP_AUTH_USER'] );
			return true;
		} else {
			return $username.' is not admin user.';
		}
	} else if ( isset( $_REQUEST['username'] ) && isset( $_REQUEST['password'] )
			&& !empty( $_REQUEST['username'] ) && !empty( $_REQUEST['password']  ) ) {

		if ( !ldap_environment_check() ) {
        	die( 'Invalid configuration for YOURLS LDAP plugin. Check PHP error log.' );
    	}	

		// try to authenticate
		$ldapConnection = ldap_connect(LDAP_HOST, LDAP_PORT);
		if (!$ldapConnection) Die("Cannot connect to LDAP " . LDAP_HOST);
		$searchDn = ldap_search($ldapConnection, LDAP_BASE, LDAP_USERNAME_FIELD . "=" . $_REQUEST['username'] );
		if (!$searchDn) return $value;
		$searchResult = ldap_get_entries($ldapConnection, $searchDn);
		if (!$searchResult) return $value;
		$userDn = $searchResult[0]['dn'];
		if (!$userDn) return $value;	
		$ldap_login = @ldap_bind($ldapConnection, $userDn, $_REQUEST['password']);
		@ldap_close($ldapConnection);

		// success?
		if ($ldap_login)
		{
			$username = $searchResult[0][LDAP_USERNAME_FIELD][0];
			yourls_set_user($username);
			$_SESSION['LDAP_AUTH_USER'] = $username;
			return true;
		}
	}

	return $value;
}

function ldap_is_authorized_user( $username ) {
	// by default, anybody who can authenticate is also
	// authorized as an administrator.
	if ( LDAP_ALL_USERS_ADMIN ) {
		return true;
	}

	// users listed in config.php are admin users. let them in.
	global $ldap_authorized_admins;
	if ( in_array( $username, $ldap_authorized_admins ) ) {
		return true;
	}

	// not an admin user
	return false;
}

yourls_add_action( 'logout', 'ldap_logout_hook' );

function ldap_logout_hook( $args ) {
	unset($_SESSION['LDAP_AUTH_USER']);
	setcookie('PHPSESSID', '', 0, '/');
}
