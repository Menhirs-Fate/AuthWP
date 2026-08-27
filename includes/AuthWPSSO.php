<?php
/**
 * SSO redirect flow for AuthWP.
 *
 * Password-based authentication through the REST bridge cannot work for
 * WordPress accounts protected by 2FA: wp_authenticate() runs the full
 * `authenticate` filter chain, which is exactly where every 2FA plugin
 * rejects a password-only attempt. Application Passwords are the documented
 * escape hatch, but they bypass 2FA and are disabled site-wide by choice.
 *
 * This provider sidesteps the problem instead of fighting it. The user is
 * redirected to WordPress, authenticates on WordPress's own login form
 * (password + whatever second factor is configured), and comes back with a
 * single-use code that MediaWiki redeems server-to-server. No password and
 * no 2FA code ever passes through this extension, and nothing here depends
 * on any security plugin's internals - so security-plugin upgrades cannot
 * break it.
 *
 * Flow:
 *   1. beginPrimaryAuthentication() generates `state`, stores it in the
 *      AuthManager session, and redirects to WordPress.
 *   2. WordPress authenticates the user and redirects to
 *      Special:AuthWPReturn with `code` + `state`.
 *   3. SpecialAuthWPReturn verifies `state`, redeems the code over the
 *      existing secret + IP-restricted channel, stashes the result, and
 *      returns the user to Special:UserLogin.
 *   4. continuePrimaryAuthentication() reads the stashed result and
 *      completes the login.
 */

use MediaWiki\Auth\AbstractPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\ButtonAuthenticationRequest;
use MediaWiki\SpecialPage\SpecialPage;

/**
 * The button rendered on Special:UserLogin that starts the flow.
 *
 * Must be a ButtonAuthenticationRequest: a plain AuthenticationRequest with
 * no fields renders nothing at all, leaving no way to trigger SSO.
 */
class AuthWPSSOBeginRequest extends ButtonAuthenticationRequest {

    public function __construct() {
        parent::__construct(
            'authwpsso',
            wfMessage( 'authwp-sso-button-label' ),
            wfMessage( 'authwp-sso-button-help' ),
            true
        );
    }

    public function describeCredentials() {
        return [
            'provider' => wfMessage( 'authwp-sso-provider-name' ),
            'account'  => wfMessage( 'authwp-sso-provider-name' ),
        ];
    }
}

/**
 * Marker request used to resume the flow after the redirect. Carries no
 * user-supplied fields: everything it needs was stashed in the AuthManager
 * session by SpecialAuthWPReturn, which is the only thing that can write it.
 */
class AuthWPSSOContinueRequest extends AuthenticationRequest {

    public function getFieldInfo() {
        return [];
    }
}

class AuthWPSSOProvider extends AbstractPrimaryAuthenticationProvider {

    /** Session key holding the CSRF state we generated. */
    public const STATE_KEY = 'AuthWPSSOState';

    /** Session key holding the redeemed identity, written by the return page. */
    public const RESULT_KEY = 'AuthWPSSOResult';

    /**
     * Off by default. The MediaWiki half can therefore be deployed and sit
     * inert until the WordPress half is live and $wgAuthWPSSOEnabled is
     * flipped on - nothing changes for users in the meantime.
     *
     * @return bool
     */
    private static function isEnabled() {
        $config = \MediaWiki\MediaWikiServices::getInstance()
            ->getConfigFactory()->makeConfig( 'AuthWP' );
        return $config->has( 'AuthWPSSOEnabled' )
            && (bool)$config->get( 'AuthWPSSOEnabled' );
    }

    public function getAuthenticationRequests( $action, array $options ) {
        if ( $action === AuthManager::ACTION_LOGIN && self::isEnabled() ) {
            return [ new AuthWPSSOBeginRequest() ];
        }
        return [];
    }

    public function beginPrimaryAuthentication( array $reqs ) {
        if ( !self::isEnabled() ) {
            return AuthenticationResponse::newAbstain();
        }

        $req = AuthenticationRequest::getRequestByClass(
            $reqs, AuthWPSSOBeginRequest::class );
        if ( !$req ) {
            // Not our button - let the password provider handle it.
            return AuthenticationResponse::newAbstain();
        }

        $startUrl = AuthWPRestClient::ssoStartUrl();
        if ( !$startUrl ) {
            wfDebugLog( 'AuthWP', 'SSO: no start URL configured' );
            return AuthenticationResponse::newFail(
                wfMessage( 'authwp-sso-misconfigured' ) );
        }

        // 48 hex chars from a CSPRNG. Bound to this session and echoed back
        // by WordPress so a third party cannot start a login for someone else.
        $state = bin2hex( random_bytes( 24 ) );
        $this->manager->setAuthenticationSessionData( self::STATE_KEY, $state );

        $returnUrl = SpecialPage::getTitleFor( 'AuthWPReturn' )
            ->getFullURL( '', false, PROTO_HTTPS );

        $url = wfAppendQuery( $startUrl, [
            'authwp_sso'   => '1',
            'redirect_uri' => $returnUrl,
            'state'        => $state,
        ] );

        wfDebugLog( 'AuthWP', "SSO: redirecting to WordPress, return=$returnUrl" );

        return AuthenticationResponse::newRedirect(
            [ new AuthWPSSOContinueRequest() ], $url );
    }

    public function continuePrimaryAuthentication( array $reqs ) {
        $result = $this->manager->getAuthenticationSessionData( self::RESULT_KEY );

        // Single use: clear it whatever happens below, so a stale result can
        // never be replayed into a second login.
        $this->manager->removeAuthenticationSessionData( self::RESULT_KEY );
        $this->manager->removeAuthenticationSessionData( self::STATE_KEY );

        if ( !is_array( $result ) || empty( $result['user_login'] ) ) {
            wfDebugLog( 'AuthWP', 'SSO: continue called with no stashed result' );
            return AuthenticationResponse::newFail(
                wfMessage( 'authwp-sso-failed' ) );
        }

        $wpUsername = $result['user_login'];
        $roles      = $result['roles'] ?? [];

        if ( !AuthWPAuthenticationProvider::isRoleAllowedFromRoles( $roles ) ) {
            wfDebugLog( 'AuthWP', "SSO: role check failed for '$wpUsername'" );
            return AuthenticationResponse::newFail(
                wfMessage( 'authwp-staff-only' ) );
        }

        // Reuse the existing rename mapping so a wiki account that was renamed
        // still resolves to the right local user.
        $mwUsername = AuthWPAuthenticationProvider::resolveRenamedUserPublic( $wpUsername );

        wfDebugLog( 'AuthWP',
            "SSO: authenticated '$wpUsername' -> MW '$mwUsername', roles="
            . json_encode( $roles ) );

        AuthWPAuthenticationProvider::rememberSsoContext( $wpUsername, $roles );

        return AuthenticationResponse::newPass( $mwUsername );
    }

    // $flags defaults to 0 (READ_NORMAL) rather than a class constant: the
    // constant moved between IDBAccessObject and User across releases, and a
    // differing default is signature-compatible anyway.
    public function testUserExists( $username, $flags = 0 ) {
        // Identity is asserted by WordPress during the redirect, not looked
        // up here. Returning false keeps this provider out of existence
        // checks it has no authority over.
        return false;
    }

    public function providerAllowsAuthenticationDataChange(
        AuthenticationRequest $req, $checkData = true
    ) {
        return \StatusValue::newGood( 'ignored' );
    }

    public function providerChangeAuthenticationData( AuthenticationRequest $req ) {
        // Credentials live in WordPress; nothing to change here.
    }

    public function accountCreationType() {
        return self::TYPE_NONE;
    }

    public function beginPrimaryAccountCreation( $user, $creator, array $reqs ) {
        return AuthenticationResponse::newAbstain();
    }
}
