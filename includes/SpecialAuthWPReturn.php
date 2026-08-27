<?php
/**
 * Landing page for the AuthWP SSO redirect flow.
 *
 * WordPress sends the user here with `code` and `state` after they have
 * authenticated on WordPress's own login form. This page verifies the state
 * against the value stored in the AuthManager session, redeems the code
 * server-to-server, stashes the resulting identity, and hands control back
 * to Special:UserLogin so AuthManager can finish the login.
 *
 * The code arrives via the user's browser, so it is treated as a bearer
 * token: short-lived, single-use, and useless without the shared secret
 * needed to redeem it.
 */

use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\MediaWikiServices;
use MediaWiki\SpecialPage\UnlistedSpecialPage;
use MediaWiki\Title\Title;

class SpecialAuthWPReturn extends UnlistedSpecialPage {

    public function __construct() {
        parent::__construct( 'AuthWPReturn' );
    }

    public function execute( $par ) {
        $this->setHeaders();
        $this->getOutput()->disallowUserJs();

        $request     = $this->getRequest();
        $authManager = MediaWikiServices::getInstance()->getAuthManager();

        $code  = (string)$request->getVal( 'code', '' );
        $state = (string)$request->getVal( 'state', '' );

        $expectedState = $authManager->getAuthenticationSessionData(
            AuthWPSSOProvider::STATE_KEY );

        // The state must match the value generated when this login started.
        // Without this check, an attacker could feed a victim a code minted
        // for the attacker's own WordPress account and have the victim's
        // browser complete a login as the attacker - session fixation.
        if ( $expectedState === null || $state === ''
            || !hash_equals( (string)$expectedState, $state ) ) {
            wfDebugLog( 'AuthWP', 'SSO return: state mismatch or no pending login' );
            $this->fail( 'authwp-sso-state-mismatch' );
            return;
        }

        if ( $code === '' ) {
            wfDebugLog( 'AuthWP', 'SSO return: no code supplied' );
            $this->fail( 'authwp-sso-failed' );
            return;
        }

        $result = AuthWPRestClient::ssoExchange( $code, $state );

        if ( $result === null ) {
            // Transport-level failure: bridge unreachable, bad secret, or a
            // non-JSON response. Distinct from "code rejected".
            wfDebugLog( 'AuthWP', 'SSO return: bridge unreachable during exchange' );
            $this->fail( 'authwp-bridge-error' );
            return;
        }

        if ( empty( $result['authenticated'] ) || empty( $result['user'] ) ) {
            wfDebugLog( 'AuthWP', 'SSO return: exchange rejected the code' );
            $this->fail( 'authwp-sso-failed' );
            return;
        }

        $user = $result['user'];

        // Stash only what the provider needs. This is the sole writer of
        // RESULT_KEY, and continuePrimaryAuthentication() clears it on read.
        $authManager->setAuthenticationSessionData(
            AuthWPSSOProvider::RESULT_KEY,
            [
                'user_login' => $user['user_login'] ?? '',
                'roles'      => (array)( $user['roles'] ?? [] ),
            ]
        );

        wfDebugLog( 'AuthWP', 'SSO return: code redeemed, resuming login for "'
            . ( $user['user_login'] ?? '?' ) . '"' );

        // Complete the login here rather than redirecting to Special:UserLogin.
        //
        // A plain redirect does NOT resume a pending AuthManager flow: the
        // login page simply renders a fresh form, so the user lands back where
        // they started, still logged out and with no explanation. The
        // continuation has to be driven explicitly.
        $continueReq = new AuthWPSSOContinueRequest();
        $continueReq->action = AuthManager::ACTION_LOGIN;

        $response = $authManager->continueAuthentication( [ $continueReq ] );

        if ( $response->status === AuthenticationResponse::PASS ) {
            wfDebugLog( 'AuthWP', 'SSO return: login complete for "'
                . $response->username . '"' );
            $this->getOutput()->redirect( $this->successTarget() );
            return;
        }

        if ( $response->status === AuthenticationResponse::FAIL ) {
            wfDebugLog( 'AuthWP', 'SSO return: continuation failed - '
                . ( $response->message ? $response->message->getKey() : 'no message' ) );
            $out = $this->getOutput();
            $out->setStatusCode( 403 );
            if ( $response->message ) {
                $out->addWikiMsg( $response->message->getKey() );
            } else {
                $out->addWikiMsg( 'authwp-sso-failed' );
            }
            $out->addWikiMsg( 'authwp-sso-retry' );
            return;
        }

        // UI / REDIRECT / RESTART are not expected: our provider returns only
        // PASS or FAIL from continuePrimaryAuthentication(). Report rather
        // than silently bouncing the user back to a blank login form.
        wfDebugLog( 'AuthWP', 'SSO return: unexpected continuation status '
            . $response->status );
        $this->fail( 'authwp-sso-failed' );
    }

    /**
     * Where to send the user once they are logged in.
     *
     * The SSO round trip leaves the wiki entirely, so MediaWiki's usual
     * returnto handling does not survive it. Honour an explicit returnto if
     * one came back with the request, otherwise the main page - anything is
     * better than redisplaying the login form to someone who just logged in.
     *
     * @return string
     */
    private function successTarget() {
        $returnTo = (string)$this->getRequest()->getVal( 'returnto', '' );
        if ( $returnTo !== '' ) {
            $title = Title::newFromText( $returnTo );
            if ( $title && $title->isKnown() ) {
                return $title->getFullURL();
            }
        }
        return Title::newMainPage()->getFullURL();
    }

    /**
     * Show an error and clear any half-finished SSO state, so a failed
     * attempt cannot leave a stale code or state usable by a later request.
     *
     * @param string $messageKey
     */
    private function fail( $messageKey ) {
        $authManager = MediaWikiServices::getInstance()->getAuthManager();
        $authManager->removeAuthenticationSessionData( AuthWPSSOProvider::STATE_KEY );
        $authManager->removeAuthenticationSessionData( AuthWPSSOProvider::RESULT_KEY );

        $out = $this->getOutput();
        $out->setStatusCode( 400 );
        $out->addWikiMsg( $messageKey );
        $out->addWikiMsg( 'authwp-sso-retry' );
    }

    public function requiresUnblock() {
        return false;
    }

    protected function getGroupName() {
        return 'login';
    }
}
