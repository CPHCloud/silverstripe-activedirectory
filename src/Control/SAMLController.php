<?php

namespace SilverStripe\ActiveDirectory\Control;

use Exception;
use OneLogin_Saml2_Error;
use SilverStripe\ActiveDirectory\Model\LDAPUtil;
use SilverStripe\Control\Controller;
use SilverStripe\Control\Director;
use SilverStripe\Control\Session;
use SilverStripe\Core\Injector\Injector;
use SilverStripe\Forms\Form;
use SilverStripe\Security\Member;
use SilverStripe\Security\Security;
use SilverStripe\ORM\ValidationResult;

/**
 * Class SAMLController
 *
 * This controller handles serving metadata requests for the IdP, as well as handling
 * creating new users and logging them into SilverStripe after being authenticated at the IdP.
 *
 * @package activedirectory
 */
class SAMLController extends Controller
{
    /**
     * @var array
     */
    private static $allowed_actions = [
        'index',
        'login',
        'logout',
        'acs',
        'sls',
        'metadata'
    ];

    /**
     * Login
     *
     * @throws OneLogin_Saml2_Error
     */
    public function login()
    {
        // Instead of sending AuthNRequest, let's send
        // a redirection to the IdP-initiaited SSO endpoint
        //$auth = Injector::inst()->get('SilverStripe\\ActiveDirectory\\Helpers\\SAMLHelper')->getSAMLAuth();
        //$auth->login();
        $idpSSOURL = Config::inst()->get('SilverStripe\\ActiveDirectory\\Services\\SAMLConfiguration', 'ssoUrl');

        return $this->redirect($idpSSOURL);
    }

    /**
     * Login
     *
     * @throws OneLogin_Saml2_Error
     */
    public function logout()
    {
        // Instead of sending AuthNRequest, let's send
        // a redirection to the IdP-initiaited SSO endpoint
        // $auth = Injector::inst()->get('SilverStripe\\ActiveDirectory\\Helpers\\SAMLHelper')->getSAMLAuth();
        // $auth->logout();
        if (array_key_exists('logged', $_GET) && $_GET['logged'] == 0) {
            $member = Member::currentUser();
            if ($member) {
                $member->logOut();
            }
            return $this->getRedirect();
        }

        //TODO this should not be hard coded - but it seems we're not using it?
        $idpSLOURL = 'https://sso.cancerview.ca/EmpowerIDWebIdpForms/Logout?ReturnURL=http://cpac-staging.cphcloud.com/saml/logout?logged=0';

        return $this->redirect($idpSLOURL);
    }

    /**
     * Assertion Consumer Service
     *
     * The user gets sent back here after authenticating with the IdP, off-site.
     * The earlier redirection to the IdP can be found in the SAMLAuthenticator::authenticate.
     *
     * After this handler completes, we end up with a rudimentary Member record (which will be created on-the-fly
     * if not existent), with the user already logged in. Login triggers memberLoggedIn hooks, which allows
     * LDAP side of this module to finish off loading Member data.
     *
     * @throws OneLogin_Saml2_Error
     */
    public function acs()
    {
        $auth = Injector::inst()->get('SilverStripe\\ActiveDirectory\\Helpers\\SAMLHelper')->getSAMLAuth();

        try {
            $auth->processResponse();
        } catch (Exception $e) {
            $error = $e->getMessage();
            $this->getLogger()->error($error);
            Form::setMessage('SAMLLoginForm_LoginForm', "Authentication error: '{$error}'", ValidationResult::CAST_TEXT);
            Session::save();
            return $this->getRedirect();
        }

        $errors = $auth->getErrors();
        if (!empty($errors)) {
            $error = $auth->getLastErrorReason();
            $this->getLogger()->error($error);
            Form::setMessage('SAMLLoginForm_LoginForm', "Authentication error: '{$error}'", ValidationResult::CAST_TEXT);
            Session::save();
            return $this->getRedirect();
        }

        if (!$auth->isAuthenticated()) {
            $this->setMessage('SAMLLoginForm_LoginForm', _t('Member.ERRORWRONGCRED'), ValidationResult::CAST_TEXT);
            Session::save();
            return $this->getRedirect();
        }

        /*
           // STUFF related to LDAP that we can't use

        $decodedNameId = base64_decode($auth->getNameId());
        // check that the NameID is a binary string (which signals that it is a guid
        if (ctype_print($decodedNameId)) {
            Form::setMessage('SAMLLoginForm_LoginForm', 'Name ID provided by IdP is not a binary GUID.', 'bad');
            Session::save();
            return $this->getRedirect();
        }

        // transform the NameId to guid
        $guid = LDAPUtil::bin_to_str_guid($decodedNameId);
        if (!LDAPUtil::validGuid($guid)) {
            $errorMessage = "Not a valid GUID '{$guid}' recieved from server.";
            $this->getLogger()->error($errorMessage);
            Form::setMessage('SAMLLoginForm_LoginForm', $errorMessage, ValidationResult::CAST_TEXT);
            Session::save();
            return $this->getRedirect();
        }

        // Write a rudimentary member with basic fields on every login, so that we at least have something
        // if LDAP synchronisation fails.
        $member = Member::get()->filter('GUID', $guid)->limit(1)->first();
        if (!($member && $member->exists())) {
            $member = new Member();
            $member->GUID = $guid;
        }

        */
        $attributes = $auth->getAttributes();
        $mapping = Member::config()->claims_field_mappings;

        $userData = array();
        foreach ($mapping as $claim => $field) {
            if (!isset($attributes[$claim][0])) {
                $this->getLogger()->warn(
                    sprintf(
                        'Claim rule \'%s\' configured in LDAPMember.claims_field_mappings, but wasn\'t passed through. Please check IdP claim rules.',
                        $claim
                    )
                );
                continue;
            }
            $userData[$field] = $attributes[$claim][0];
        }

        if (!isset($userData['Email'])) {
            $error = "Email was not provided by IdP. Review internal mapping or IdP settings";
            $this->getLogger()->error($error);
            Form::setMessage('SAMLLoginForm_LoginForm', "Authentication error: '{$error}'", ValidationResult::CAST_TEXT);
        }

        $member = Member::get()->filter('Email', $userData['Email'])->limit(1)->first();
        if (!($member && $member->exists())) {
            $member = new Member();
            $member->Email = $userData['Email'];
        }
        foreach ($userData as $field => $value) {
            if ($field != 'Email') {
                $member->$field = $value;
            }
        }

        $member->SAMLSessionIndex = $auth->getSessionIndex();

        // This will trigger LDAP update through LDAPMemberExtension::memberLoggedIn.
        // The LDAP update will also write the Member record. We shouldn't write before
        // calling this, as any onAfterWrite hooks that attempt to update LDAP won't
        // have the Username field available yet for new Member records, and fail.
        // Both SAML and LDAP identify Members by the GUID field.
        $member->logIn();

        return $this->getRedirect();
    }

   /**
     * Single Logout Service
     *
     * @throws OneLogin_Saml2_Error
     */
    public function sls()
    {
        $auth = Injector::inst()->get('SilverStripe\\ActiveDirectory\\Helpers\\SAMLHelper')->getSAMLAuth();

        // TODO I need to execute local logout instead
        // clean the session
        $auth->processSLO();

        $errors = $auth->getErrors();
        if (!empty($errors)) {
            $error = $auth->getLastErrorReason();
            $this->getLogger()->error($error);
            $this->setMessage('SAMLLoginForm_LoginForm', "Authentication error: '{$error}'", 'bad');
            Session::save();
            return $this->getRedirect();
        } else {
            $member = Member::currentUser();
            if ($member) {
                $member->logOut();
            }

            // Successfully logged out
            return $this->getRedirect();
        }
    }

    /**
     * Generate this SP's metadata. This is needed for intialising the SP-IdP relationship.
     * IdP is instructed to call us back here to establish the relationship. IdP may also be configured
     * to hit this endpoint periodically during normal operation, to check the SP availability.
     */
    public function metadata()
    {
        try {
            $auth = Injector::inst()->get('SilverStripe\\ActiveDirectory\\Helpers\\SAMLHelper')->getSAMLAuth();
            $settings = $auth->getSettings();
            $metadata = $settings->getSPMetadata();
            $errors = $settings->validateMetadata($metadata);
            if (empty($errors)) {
                header('Content-Type: text/xml');
                echo $metadata;
            } else {
                throw new \OneLogin_Saml2_Error(
                    'Invalid SP metadata: ' . implode(', ', $errors),
                    \OneLogin_Saml2_Error::METADATA_SP_INVALID
                );
            }
        } catch (Exception $e) {
            $this->getLogger()->error($e->getMessage());
            echo $e->getMessage();
        }
    }

    /**
     * @return SS_HTTPResponse
     */
    protected function getRedirect()
    {
        // Absolute redirection URLs may cause spoofing
        if (Session::get('BackURL') && Director::is_site_url(Session::get('BackURL'))) {
            return $this->redirect(Session::get('BackURL'));
        }

        // Spoofing attack, redirect to homepage instead of spoofing url
        if (Session::get('BackURL') && !Director::is_site_url(Session::get('BackURL'))) {
            return $this->redirect(Director::absoluteBaseURL());
        }

        // If a default login dest has been set, redirect to that.
        if (Security::config()->default_login_dest) {
            return $this->redirect(Director::absoluteBaseURL() . Security::config()->default_login_dest);
        }

        // fallback to redirect back to home page
        return $this->redirect(Director::absoluteBaseURL());
    }

    /**
     * Get a logger
     *
     * @return Psr\Log\LoggerInterface
     */
    public function getLogger()
    {
        return Injector::inst()->get('Logger');
    }
}
