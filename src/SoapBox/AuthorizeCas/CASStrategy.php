<?php namespace SoapBox\AuthorizeCas;

use \phpCAS;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Exceptions\AuthenticationException;
use SoapBox\Authorize\Strategies\SingleSignOnStrategy;

class CASStrategy extends SingleSignOnStrategy {

	/**
	 * Initializes the Cas
	 *
	 * @param array $settings array('host' => string, 'port' => int, 'context' => ???)
	 * @param callable $store A callback that will store a KVP (Key Value Pair).
	 * @param callable $load A callback that will return a value stored with the
	 *	provided key.
	 */
	public function __construct($settings = array(), $store = null, $load = null) {
		if( !isset($settings['host']) ||
			!isset($settings['port']) ||
			!isset($settings['context']) ||
			!isset($settings['ca_cert']) ) {
			throw new MissingArgumentsException(
				'Required parameters host, port, context, or ca_cert are missing'
			);
		}

		// Disable debugging
		phpCAS::setDebug(false);

		phpCAS::client(
			SAML_VERSION_1_1,
			$settings['host'],
			$settings['port'],
			$settings['context']
		);

		phpCAS::setCasServerCACert($settings['ca_cert']);
	}

	/**
	 * Used to authenticate our user through one of the various methods.
	 *
	 * @param array parameters array()
	 *
	 * @throws AuthenticationException If the provided parameters do not
	 *	successfully authenticate.
	 *
	 * @return User A mixed array repreesnting the authenticated user.
	 */
	public function login($parameters = array()) {
		phpCAS::forceAuthentication();
		return $this->getUser($parameters);
	}

	public function getUser($parameters = array()) {
		try {
			$user = new User;
			$casUser = phpCAS::getAttributes();

			$user->id = phpCAS::getUser() . '@ryerson.ca';
			$user->email = phpCAS::getUser() . '@ryerson.ca';
			$user->accessToken = '';
			$user->firstname = $casUser['firstname'];
			$user->lastname = $casUser['lastname'];

			return $user;
		} catch (\Exception $ex) {
			throw new AuthenticationException();
		}
	}

	public function endpoint($parameters = array()) {
		return $this->login($parameters);
	}
}
