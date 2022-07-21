# Silverstripe Robots.txt

[![Version](http://img.shields.io/packagist/v/innoweb/silverstripe-common-password-validation.svg?style=flat-square)](https://packagist.org/packages/innoweb/silverstripe-common-password-validation)
[![License](http://img.shields.io/packagist/l/innoweb/silverstripe-common-password-validation.svg?style=flat-square)](license.md)

## Overview

Adds additional validation steps to PasswordValidator to check for common passwords, the member's name and repeated characters.

## Requirements

* Silverstripe Framework ^4.11

## Installation

Install the module using composer:
```
composer require innoweb/silverstripe-common-password-validation dev-master
```
Then run dev/build.

## Configuration

You can configure what tests should be performed. All three tests are enabled by default.

```yml
SilverStripe\Security\PasswordValidator:
  check_repetitions: false
  check_member_name: false
  check_common_passwords: false
```

You can edit the list of common passwords used. 

```yml
SilverStripe\Security\PasswordValidator:
  common_passwords:
    - 'something'
```

The module currently uses a list of passwords collected from [Nord Pass](https://nordpass.com/most-common-passwords-list/) and [Daniel Miesler](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt).

## License

BSD 3-Clause License, see [License](license.md)