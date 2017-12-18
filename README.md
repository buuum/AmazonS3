# AmazonS3 - Simple Amazon S3 class
===============================

[![Packagist](https://img.shields.io/packagist/v/buuum/amazons3.svg)](https://packagist.org/packages/buuum/amazons3)
[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](#license)

## Install

### System Requirements

You need PHP >= 5.5.0 to use Buuum\AmazonS3 but the latest stable version of PHP is recommended.

### Composer

Buuum\S3 is available on Packagist and can be installed using Composer:

```
composer require buuum/amazons3
```

### Manually

You may use your own autoloader as long as it follows PSR-0 or PSR-4 standards. Just put src directory contents in your vendor directory.

## CONSTANTS

```php
const ACL_PRIVATE = 'private';
const ACL_PUBLIC_READ = 'public-read';
const ACL_PUBLIC_READ_WRITE = 'public-read-write';
const ACL_AUTHENTICATED_READ = 'authenticated-read';

const STORAGE_CLASS_STANDARD = 'STANDARD';
const STORAGE_CLASS_RRS = 'REDUCED_REDUNDANCY';
const STORAGE_CLASS_STANDARD_IA = 'STANDARD_IA';
```

## USAGE

### INITIALIZE
```php
$s3 = new S3($config_key, $config_secret, $config_bucket);
$s3->setDefaultHeaders([
    'Cache-Control' => 'max-age=2592000',
    'Expires'       => 2592000,
]);
```