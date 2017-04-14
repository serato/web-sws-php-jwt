# Serato Web Services PHP JWT

A PHP library containing common functionality for working with JWTs witin
Serato Web Services web applications.

## Style guide

Please ensure code adheres to the [PHP-FIG PSR-2 Coding Style Guide](http://www.php-fig.org/psr/psr-2/)

Use [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer/wiki) to validate your code against coding standards:

	$ ./vendor/bin/phpcs --standard=SWS-JWT

## Unit tests

Configuration for PHPUnit is defined within [phpunit.xml](phpunit.xml).

To run tests:

	$ php vendor/bin/phpunit -c phpunit.xml

See [PHPUnit documentation](https://phpunit.de/manual/current/en/index.html) for more options.

## Generate PHP API documentation

The [Sami PHP API documentation generator](https://github.com/FriendsOfPHP/sami)
can be used to generate PHP API documentation.

To generate documentation:

	$ php sami.phar update phpdoc.php

Note: Must be run on PHP 7.* system.

Documentation is generated into the `docs\php` directory (which is not under source control).

Configuration for Sami is contained within [phpdoc.php](phpdoc.php).
