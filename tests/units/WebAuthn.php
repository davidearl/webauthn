<?php

namespace test\units\Davidearl\WebAuthn;

use atoum;

class WebAuthn extends atoum
{
    public function testPublicKeyOptions()
    {
        $this
            ->given($this->newTestedInstance('app.com'))
            ->then
                ->string($this->testedInstance->prepareChallengeForRegistration('test', 123))
                ->isNotEmpty();
    }
}
