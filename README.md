# Serato Web Services PHP JWT [![Build Status](https://img.shields.io/travis/serato/web-sws-php-jwt.svg)](https://travis-ci.org/serato/web-sws-php-jwt)

[![Latest Stable Version](https://img.shields.io/packagist/v/serato/jwt.svg)](https://packagist.org/packages/serato/jwt)

A PHP library containing common functionality for working with JWTs witin
Serato Web Services web applications.

## Adding to a project via composer.json

To include this library in a PHP project add the following line to the project's
`composer.json` file in the `require` section:

```json
{
	"require": {
		"serato/jwt": "~1.0"
	}
}
```
See [Packagist](https://packagist.org/packages/serato/jwt) for a list of all 
available versions.

## Style guide

Please ensure code adheres to the [PHP-FIG PSR-2 Coding Style Guide](http://www.php-fig.org/psr/psr-2/)

Use [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer/wiki) to validate your code against coding standards:

```bash
$ ./vendor/bin/phpcs
```

## PHPStan

Use PHPStan for static code analysis:

```bash
$ vendor/bin/phpstan analyse
```

## Unit tests

Configuration for PHPUnit is defined within [phpunit.xml](phpunit.xml).

To run tests:

```bash
$ php vendor/bin/phpunit
```

See [PHPUnit documentation](https://phpunit.de/manual/current/en/index.html) for more options.

## Using Docker to develop this library.

Use the provided [docker-compose.yml](./docker-compose.yml) file to develop this library.

```bash
# Run the `php-build` service using the default PHP version (7.1) and remove the container after use.
docker-compose run --rm  php-build

# Provide an alternative PHP version via the PHP_VERSION environment variable.
PHP_VERSION=7.2 docker-compose run --rm  php-build
```

When Docker Compose runs the container it executes [docker.sh](./docker.sh).

This script installs some required packages, installs [Composer](https://getcomposer.org/) and performs a `composer install` for this PHP library.

It then opens a bash shell for interacting with the running container.

### AWS credentials for integration tests

To run integration tests that interact with AWS services provide an IAM access key and secret via the `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables.

```bash
AWS_ACCESS_KEY_ID=my_key_id AWS_SECRET_ACCESS_KEY=my_key_secret docker-compose run --rm  php-build
```
