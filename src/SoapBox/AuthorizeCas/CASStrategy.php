<?php namespace SoapBox\AuthorizeCas;

use \phpCAS;
use SoapBox\Authorize\User;
use SoapBox\Authorize\Strategies\SingleSignOnStrategy;
use SoapBox\Authorize\Exceptions\AuthenticationException;

class CASStrategy extends SingleSignOnStrategy {

	protected $host;

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
			!isset($settings['redirect_url']) ||
			!isset($settings['ca_cert']) ) {
			throw new MissingArgumentsException(
				'Required parameters host, port, context, or ca_cert are missing'
			);
		}

		$this->host = $settings['host'];

		// Disable debugging
		phpCAS::setDebug(false);

		phpCAS::client(
			SAML_VERSION_1_1,
			$settings['host'],
			(int) $settings['port'],
			$settings['context']
		);

		phpCAS::setCasServerCACert($settings['ca_cert']);

		phpCAS::setFixedServiceURL($settings['redirect_url']);
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
			$attributes = phpCAS::getAttributes();

			$fields = $parameters['parameters_map'];

			$user->username = phpCAS::getUser();

			$user->email = $user->username;
			if (isset($fields['email'])) {
				$user->email = $attributes[$fields['email']];
			}

			$user->id = $user->username;
			if (isset($fields['id'])) {
				$user->id = $attributes[$fields['id']];
			}

			$user->firstname = $attributes[$fields['firstname']];
			$user->lastname = $attributes[$fields['lastname']];

			$user->accessToken = 'token';

			if (isset($fields['additional_attributes'])) {
				$additionalAttributes = json_decode($fields['additional_attributes'], true);

				foreach ($additionalAttributes as $key => $value) {
					if (isset($attributes[$value])) {
						$user->custom[$key] = $attributes[$value];
					}
				}
			}

			return $user;
		} catch (\Exception $ex) {
			throw new AuthenticationException(null, 0, $ex);
		}
	}

	public function endpoint($parameters = array()) {
		return $this->login($parameters);
	}

	public function signout($redirectUrl) {
		phpCAS::handleLogoutRequests(true, [$this->host]);
		phpCAS::logout(
			['url'=>$redirectUrl]
		);
	}
}
