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
	public function __construct($settings = []) {
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
	 * This method is called to force authentication if the user was not already
     * authenticated. If the user is not authenticated, halt by redirecting to
     * the CAS server.
	 *
	 * @param array $parameters Empty array
	 * @param Closure $store Closure to handle the storage of session data
	 * @param Closure $redirect Closure to handle the redirection of a user to the cas Auth site
	 *
	 * @return bool True if logged in
	 */
	public function login($parameters = []) {
		return phpCAS::forceAuthentication();
	}

	/**
	 * Used to retrieve the user from the strategy.
	 *
	 * @param mixed[] $parameters The additional parameters required to authenticate
	 *
	 * @throws AuthenticationException If the provided parameters do not
	 *	successfully authenticate.
	 *
	 * @return User The user retieved from the Strategy
	 */
	public function getUser($parameters = []) {
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
			throw new AuthenticationException(null, 0, $ex);
		}
	}
}
