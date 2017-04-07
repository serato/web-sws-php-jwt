# Serato Web Services PHP JWT

A PHP library containing common functionality for working with JWTs witin
Serato Web Services web applications.

## Style guide

Please ensure code adheres to the [PHP-FIG PSR-2 Coding Style Guide](http://www.php-fig.org/psr/psr-2/)

Use [PHP_CodeSniffer](https://github.com/squizlabs/PHP_CodeSniffer/wiki) to validate your code against coding standards:

	$ ./vendor/bin/phpcs --standard=SWS-JWT

## Unit tests

Configuration for PHPUnit is defined within [phpunit.xml](phpunit.xml). Additional information pertaining to PHPUnit usage within this project can be found in [this README](./tests/README.md)

To run tests:

	$ php vendor/bin/phpunit -c phpunit.xml

See [PHPUnit documentation](https://phpunit.de/manual/current/en/index.html) for more options.
