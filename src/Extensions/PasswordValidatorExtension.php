<?php

namespace Innoweb\CommonPasswordValidation\Extensions;

use Exception;
use SilverStripe\Core\Extension;
use SilverStripe\ORM\ValidationResult;
use SilverStripe\Security\Member;

class PasswordValidatorExtension extends Extension
{
    private static $check_repetitions = true;
    private static $check_member_name = true;
    private static $check_common_passwords = true;

    private static $common_passwords = [];
    private static $levenshtein_distance = 2;

    public function updateValidatePassword(string $password, Member $member, ValidationResult $valid)
    {
        // check repeated characters
        if ($this->getOwner()->config()->get('check_repetitions')) {
            try {
                $this->getOwner()->checkRepetitions($password);
            } catch (Exception $e) {
                $error = _t(
                    'PasswordValidator.CANNOTUSE',
                    'You cannot use that password: {message}',
                    ['message' => $e->getMessage()]
                );
                $valid->addError($error, 'bad', 'REPETITION');
            }
        }
        // check user's own name
        if ($this->getOwner()->config()->get('check_member_name')) {
            try {
                $this->getOwner()->checkMemberName($password, $member);
            } catch (Exception $e) {
                $error = _t(
                    'PasswordValidator.CANNOTUSE',
                    'You cannot use that password: {message}',
                    ['message' => $e->getMessage()]
                );
                $valid->addError($error, 'bad', 'NAME');
            }
        }
        // check common passwords
        if ($this->getOwner()->config()->get('check_common_passwords')) {
            try {
                $this->getOwner()->checkCommonPasswords($password);
            } catch (Exception $e) {
                $error = _t(
                    'PasswordValidator.CANNOTUSE',
                    'You cannot use that password: {message}',
                    ['message' => $e->getMessage()]
                );
                $valid->addError($error, 'bad', 'COMMON');
            }
        }
    }

    public function checkRepetitions(string $password)
    {
        if (!preg_match('/^(?:(.)(?!\1))*$/', $password)) { // matches string with no repetition
            // repetition detected
            throw new Exception(_t('PasswordValidator.REPETITION', "Don't repeat any characters in your password"));
        }
    }

    public function checkMemberName(string $password, Member $member)
    {
        $namesToCheck = [
            $member->FirstName,
            $member->Surname,
            $member->FirstName . $member->Surname,
            substr($member->FirstName, 0, 1) . $member->Surname,
            $member->FirstName . substr($member->Surname, 0, 1),
        ];
        $namesToCheck = array_filter($namesToCheck);
        if ($namesToCheck && count($namesToCheck)) {
            $distance = $this->getOwner()->config()->get('levenshtein_distance');
            foreach ($namesToCheck as $name) {
                if (stripos(strtolower($password), strtolower($name))) {
                    // match with a name combination
                    throw new Exception(_t('PasswordValidator.DONTUSENAME', "Don't use your name in passwords"));
                }
                $found_distance = levenshtein($password, $name);
                if ($found_distance <= $distance) {
                    // similar to a name combination
                    throw new Exception(_t('PasswordValidator.DONTUSENAMEVARIATION', "Don't use your name in passwords"));
                }
            }
        }
    }

    public function checkCommonPasswords(string $password)
    {
        $common_passwords = $this->getOwner()->config()->get('common_passwords');
        if ($common_passwords && count($common_passwords)) {
            $distance = $this->getOwner()->config()->get('levenshtein_distance');
            foreach ($common_passwords as $common_password) {
                if (strtolower($password) == strtolower($common_password)) {
                    // match with a common password
                    throw new Exception(_t('PasswordValidator.TOOCOMMON', "Password is too common"));
                }
                $found_distance = levenshtein(strtolower($password), strtolower($common_password));
                if ($found_distance <= $distance) {
                    throw new Exception(_t('PasswordValidator.FAIRLYCOMMON', "Password looks fairly common"));
                }
            }
        }
    }
}

