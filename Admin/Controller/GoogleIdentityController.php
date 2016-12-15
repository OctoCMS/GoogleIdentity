<?php

namespace Octo\GoogleIdentity\Admin\Controller;

use b8\Form\Element\Checkbox;
use b8\Form\Element\Submit;
use b8\Form\Element\Text;
use b8\Form\FieldSet;
use Octo\Admin\Controller;
use Octo\Admin\Menu;
use Octo\Admin\Form as FormElement;
use Octo\Event;
use Octo\Form\Element\OnOffSwitch;
use Octo\GoogleIdentity\GoogleLoginButton;
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
        $email = $this->getParam('email', '');
        $token = $this->getParam('token', '');

        $client = new \Google_Client();
        $client->setClientId(Setting::get('google-identity', 'client_id'));
        $client->setClientSecret(Setting::get('google-identity', 'client_secret'));
        $client->setRedirectUri($this->config->get('site.full_admin_url').'/google-identity/auth');
        $client->setScopes('email');

        $data = $client->verifyIdToken($token)->getAttributes();

        if (empty($data['payload']['email']) || $data['payload']['email'] != $email) {
            return $this->redirect('/session/login?logout=1')
                        ->error('There was a problem signing you in, please try again.');
        }

        $userStore = Store::get('User');
        $user = $userStore->getByEmail($email);

        if (is_null($user)) {
            $authDomains = Setting::get('google-identity', 'login_auto_create');
            $authDomains = explode(',', $authDomains);
            $parts = explode('@', $email, 2);

            if (!in_array($parts[1], $authDomains)) {
                return $this->redirect('/session/login?logout=1')->error('You do not have permission to sign in.');
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

        if (isset($_SESSION['previous_url'])) {
            return $this->redirect($_SESSION['previous_url']);
        }

        return $this->redirect('/');
    }

    public function code()
    {
        $client = new \Google_Client();
        $client->setClientId(Setting::get('google-identity', 'client_id'));
        $client->setClientSecret(Setting::get('google-identity', 'client_secret'));
        $client->setRedirectUri('postmessage');
        $client->authenticate($this->getParam('code'));

        Setting::set('google-identity', 'access_token', $client->getAccessToken());

        return $this->info();
    }

    public function info()
    {
        try {
            $token = Setting::get('google-identity', 'access_token');

            if (empty($token)) {
                throw new \Exception('No access token set.');
            }

            $client = new \Google_Client();
            $client->setAccessToken($token);

            $service = new \Google_Service_Oauth2($client);
            $userInfo = $service->userinfo->get();

            return $this->json([
                'success' => true,
                'name' => $userInfo->name,
                'email' => $userInfo->email,
                'photo' => $userInfo->picture,
            ]);
        } catch (\Exception $ex) {
            Setting::set('google-identity', 'access_token', null);

            return $this->json([
                'success' => false,
                'error' => $ex->getMessage(),
            ]);
        }
    }

    public function logout()
    {
        Setting::set('google-identity', 'access_token', null);
        return $this->info();
    }

    public function settings()
    {
        $this->setTitle('Google Identity');
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

        $scopes = [];
        Event::trigger('Octo.GoogleIdentity.GetScopes', $scopes);

        $this->template->scopes = implode(' ', array_unique($scopes));
        $this->template->form = $form;
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
        }

        $submit = new Submit();
        $submit->setValue('Save Settings');
        $form->addField($submit);

        return $form;
    }
}
