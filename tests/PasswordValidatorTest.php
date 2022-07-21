<?php

namespace Innoweb\CommonPasswordValidation\Tests;

use SilverStripe\Dev\SapphireTest;
use SilverStripe\Security\Member;
use SilverStripe\Security\PasswordValidator;

class PasswordValidatorTest extends SapphireTest
{
    protected function setUp(): void
    {
        parent::setUp();

        PasswordValidator::config()
            ->remove('min_length')
            ->remove('historic_count')
            ->set('min_test_score', 0)
            ->set('check_repetitions', false)
            ->set('check_member_name', false)
            ->set('check_common_passwords', false);
    }

    public function testValidateRepetitions()
    {
        PasswordValidator::config()
            ->set('check_repetitions', true);

        $v = new PasswordValidator();

        $r = $v->validate('UMp9+sF7Y?}Z#dDy%qQohLA3W*GKbB', new Member());
        $this->assertTrue($r->isValid(), 'Passwords without repetitions are valid');

        $r = $v->validate('UMp9+sF7Y?}Z#dDy%qqQohLA3W*GKbB', new Member());
        $this->assertFalse($r->isValid(), 'Passwords with repetitions are invalid');
    }

    public function testValidateMemberName()
    {
        PasswordValidator::config()
            ->set('check_member_name', true);

        $v = new PasswordValidator();

        $member = new Member();
        $member->FirstName = 'Peter';
        $member->Surname = 'Tester';

        $r = $v->validate('asdf', $member);
        $this->assertTrue($r->isValid(), 'Passwords without name are valid');

        $r = $v->validate('peter!tester', $member);
        $this->assertFalse($r->isValid(), 'Passwords that include name are invalid (1)');

        $r = $v->validate('petertester', $member);
        $this->assertFalse($r->isValid(), 'Passwords that include name are invalid (2)');

        $r = $v->validate('ptester', $member);
        $this->assertFalse($r->isValid(), 'Passwords that include name are invalid (3)');

        $r = $v->validate('petert', $member);
        $this->assertFalse($r->isValid(), 'Passwords that include name are invalid (4)');

        $r = $v->validate('123peter345', $member);
        $this->assertFalse($r->isValid(), 'Passwords that include name are invalid (5)');
    }

    public function testValidateCommonPasswords()
    {
        PasswordValidator::config()
            ->set('check_common_passwords', true)
            ->set('common_passwords', [
                'common'
            ]);

        $v = new PasswordValidator();

        $r = $v->validate('asdf', new Member());
        $this->assertTrue($r->isValid(), 'Passwords not in the common list are valid');

        $r = $v->validate('common', new Member());
        $this->assertFalse($r->isValid(), 'Passwords in the common list are invalid (1)');

        $r = $v->validate('Common', new Member());
        $this->assertFalse($r->isValid(), 'Passwords in the common list are invalid (2)');

        $r = $v->validate('comm0n', new Member());
        $this->assertFalse($r->isValid(), 'Passwords similar to the ones in the common list are invalid (1)');

        $r = $v->validate('C1mM0n', new Member());
        $this->assertFalse($r->isValid(), 'Passwords similar to the ones in the common list are invalid (2)');
    }
}
