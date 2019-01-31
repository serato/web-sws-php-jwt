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

## Requirements

This library requires PHP 7.1 or above.

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

## Generate PHP API documentation

The [Sami PHP API documentation generator](https://github.com/FriendsOfPHP/sami)
can be used to generate PHP API documentation.

To generate documentation:

```bash
$ php sami.phar update phpdoc.php
```

Documentation is generated into the `docs\php` directory.

Configuration for Sami is contained within [phpdoc.php](phpdoc.php).

## Generate code coverage report

If you have [phpdbg](http://phpdbg.com/) installed you can generate a code coverage report with phpunit:

```bash
$ phpdbg -qrr ./vendor/bin/phpunit --coverage-html tests/reports/coverage
```

Reports are generated in the `tests/reports` directory.

