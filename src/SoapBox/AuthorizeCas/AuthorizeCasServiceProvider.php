<?php namespace SoapBox\AuthorizeCas;

use Illuminate\Support\ServiceProvider;
use SoapBox\Authorize\StrategyFactory;

class AuthorizeCasServiceProvider extends ServiceProvider {

	/**
	 * Indicates if loading of the provider is deferred.
	 *
	 * @var bool
	 */
	protected $defer = true;

	/**
	 * Bootstrap the application events.
	 *
	 * @return void
	 */
	public function boot()
	{
		$this->package('soapbox/authorize-cas');
	}

	/**
	 * Register the service provider.
	 *
	 * @return void
	 */
	public function register() {
		$this->app->bind(
			'soapbox.authorize.cas',
			'SoapBox\AuthorizeCas\CASStrategy'
		);
	}

	/**
	 * Get the services provided by the provider.
	 *
	 * @return array
	 */
	public function provides() {
		return ['soapbox.authorize.cas'];
	}

}
