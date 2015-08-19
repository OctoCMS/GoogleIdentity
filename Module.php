<?php

namespace Octo\GoogleIdentity;

class Module extends \Octo\Module
{
    protected function getName()
    {
        return 'GoogleIdentity';
    }

    protected function getPath()
    {
        return dirname(__FILE__) . '/';
    }

    public function init()
    {
        $app = $this->config->get('Octo');
        $app['bypass_auth']['google-identity'] = ['auth'];
        $this->config->set('Octo', $app);

        return parent::init();
    }
}
