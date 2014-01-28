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
		//'LDAAUTHP_PORT', // ldap port
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
	// doesn't work for API...
	if (yourls_is_API())
		return $value;

	@session_start();

	if ( isset( $_SESSION['LDAPAUTH_AUTH_USER'] ) ) {
		// already authenticated...
		$username = $_SESSION['LDAPAUTH_AUTH_USER'];
		if ( ldapauth_is_authorized_user( $username ) ) {
			yourls_set_user( $_SESSION['LDAPAUTH_AUTH_USER'] );
			return true;
		} else {
			return $username.' is not admin user.';
		}
	} else if ( isset( $_REQUEST['username'] ) && isset( $_REQUEST['password'] )
			&& !empty( $_REQUEST['username'] ) && !empty( $_REQUEST['password']  ) ) {

		if ( !ldapauth_environment_check() ) {
        	die( 'Invalid configuration for YOURLS LDAP plugin. Check PHP error log.' );
    	}	

		// try to authenticate
		$ldapConnection = ldap_connect(LDAPAUTH_HOST, LDAPAUTH_PORT);
		if (!$ldapConnection) Die("Cannot connect to LDAP " . LDAPAUTH_HOST);
		ldap_set_option($ldapConnection, LDAP_OPT_PROTOCOL_VERSION, 3);
		$searchDn = ldap_search($ldapConnection, LDAPAUTH_BASE, LDAPAUTH_USERNAME_FIELD . "=" . $_REQUEST['username'] );
		if (!$searchDn) return $value;
		$searchResult = ldap_get_entries($ldapConnection, $searchDn);
		if (!$searchResult) return $value;
		$userDn = $searchResult[0]['dn'];
		if (!$userDn) return $value;	
		$ldapSuccess = @ldap_bind($ldapConnection, $userDn, $_REQUEST['password']);
		@ldap_close($ldapConnection);

		// success?
		if ($ldapSuccess)
		{
			$username = $searchResult[0][LDAPAUTH_USERNAME_FIELD][0];
			yourls_set_user($username);
			global $yourls_user_passwords;
			$yourls_user_passwords[$username] = uniqid("",true);
			$_SESSION['LDAPAUTH_AUTH_USER'] = $username;
			return true;
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
	unset($_SESSION['LDAPAUTH_AUTH_USER']);
	setcookie('PHPSESSID', '', 0, '/');
}
