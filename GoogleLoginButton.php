<?php

namespace Octo\GoogleIdentity;

use b8\Form\Input;

class GoogleLoginButton extends Input
{
    public $scopes = '';

    protected function onPreRender(&$view)
    {
        $view->scopes = $this->scopes;
        return parent::onPreRender($view);
    }
}