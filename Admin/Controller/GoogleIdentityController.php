<?php

namespace Octo\GoogleAnalytics\Admin\Controller;

use b8\Form\Element\Checkbox;
use b8\Form\Element\Submit;
use b8\Form\Element\Text;
use b8\Form\FieldSet;
use Octo\Admin\Controller;
use Octo\Admin\Menu;
use Octo\Admin\Form as FormElement;
use Octo\Form\Element\OnOffSwitch;
use Octo\Store;
use Octo\System\Model\Setting;
use Octo\System\Model\User;

class GoogleIdentityController extends Controller
{
    public static function registerMenus(Menu $menu)
    {
        $root = $menu->getRoot('Developer');
        $root->addChild(new Menu\Item('Google Identity Settings', '/google-identity/settings'));
    }

    public function auth()
    {
        $auth = 'login';

        if (array_key_exists('auth', $_SESSION)) {
            $auth = $_SESSION['auth'];
        }

        if ($auth == 'login') {
            return $this->authLogin();
        }
    }

    protected function authLogin()
    {
        $email = $this->getParam('email', '');
        $token = $this->getParam('token', '');

        $client = new \Google_Client();
        $client->setClientId(Setting::get('google-identity', 'client_id'));
        $client->setClientSecret(Setting::get('google-identity', 'client_secret'));
        $client->setRedirectUri($this->config->get('site.url').'/'.$this->config->get('site.admin_uri').'/google-identity/auth');
        $client->setScopes('email');

        $data = $client->verifyIdToken($token)->getAttributes();

        if (empty($data['payload']['email']) || $data['payload']['email'] != $email) {
            $this->errorMessage('There was a problem signing you in, please try again.', true);
            header('Location: ' . $this->config->get('site.url') . '/' . $this->config->get('site.admin_uri') . '/session/login?unauthorized=1');
            die;
        }

        $userStore = Store::get('User');
        $user = $userStore->getByEmail($email);

        if (is_null($user)) {
            $authDomains = Setting::get('google-identity', 'login_auto_create');
            $authDomains = explode(',', $authDomains);
            $parts = explode('@', $email, 2);

            if (!in_array($parts[1], $authDomains)) {
                $this->errorMessage('You do not have permission to sign in.', true);
                header('Location: ' . $this->config->get('site.url') . '/' . $this->config->get('site.admin_uri') . '/session/login?unauthorized=1');
                die;
            }

            $user = new User();
            $user->setActive(1);
            $user->setIsAdmin(1);
            $user->setDateAdded(new \DateTime());
            $user->setEmail($email);
            $user->setName($data['payload']['name']);
            $user = $userStore->save($user);
        }

        $_SESSION['user_id'] = $user->getId();
        $url = '/' . $this->config->get('site.admin_uri');

        if (isset($_SESSION['previous_url'])) {
            $url = $_SESSION['previous_url'];
        }

        header('Location: ' . $url);
        die;
    }

    public function settings()
    {
        $values = Setting::getForScope('google-identity');
        $form = $this->settingsForm($values);

        if ($this->request->getMethod() == 'POST') {
            $params = $this->getParams();
            $form->setValues($params);

            Setting::setForScope('google-identity', $form->getValues());
            $this->successMessage('Settings saved successfully.');
        } else {
            $form->setValues($values);
        }

        $this->view->form = $form;
    }

    protected function settingsForm($values)
    {
        $form = new FormElement();
        $form->setMethod('POST');

        $fieldset = new FieldSet();
        $fieldset->setId('oauth');
        $fieldset->setLabel('OAuth Details');
        $form->addField($fieldset);

        $fieldset->addField(Text::create('client_id', 'Client ID'));
        $fieldset->addField(Text::create('client_secret', 'Client Secret'));

        if (!empty($values['client_id']) && !empty($values['client_secret'])) {

            $fieldset = new FieldSet();
            $fieldset->setId('login');
            $fieldset->setLabel('Google Login');
            $form->addField($fieldset);

            $fieldset->addField(OnOffSwitch::create('login_enabled', 'Enable Google Login?', false));
            $fieldset->addField(Text::create('login_auto_create', 'Auto-approved login domains:'));


            $fieldset = new FieldSet();
            $fieldset->setId('api');
            $fieldset->setLabel('Google APIs');
            $form->addField($fieldset);

        }

        $submit = new Submit();
        $submit->setValue('Save Settings');
        $form->addField($submit);

        return $form;
    }
}
