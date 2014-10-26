# Authorize-CAS
[Authorize](http://github.com/soapbox/authorize) strategy for CAS authentication.

## Getting Started
- Install [Authorize](http://github.com/soapbox/authorize) into your application
to use this Strategy.
- Obtain the applicable settings for your CAS integration, see settings array below.

## Installation
Add the following to your `composer.json`
```
"require": {
	...
	"soapbox/authorize-cas": "1.*",
	...
}
```

### app/config/app.php
Add the following to your `app.php`, note this will be removed in future
versions since it couples us with Laravel, and it isn't required for the library
to function
```
'providers' => array(
	...
	"SoapBox\AuthorizeCas\AuthorizeCasServiceProvider",
	...
)
```

## Usage

### Login
```php

use SoapBox\Authroize\Authenticator;
use SoapBox\Authorize\Exceptions\InvalidStrategyException;
...
$settings = [
	'host'		=> 'cas.example.com',
	'port'		=> '443',
	'context'	=> '/',
	'ca_cert'	=> 'path/to/certificate'
];

$strategy = new Authenticator('cas', $settings);
$user = $strategy->authenticate($parameters);

```

### Endpoint
```php

use SoapBox\Authroize\Authenticator;
use SoapBox\Authorize\Exceptions\InvalidStrategyException;
...
$settings = [
	'host'		=> 'cas.example.com',
	'port'		=> '443',
	'context'	=> '/',
	'ca_cert'	=> 'path/to/certificate'
];

$strategy = new Authenticator('cas', $settings);
$user = $strategy->endpoint();

```
