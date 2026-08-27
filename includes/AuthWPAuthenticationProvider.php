<?php
/**
 * Copyright 2020 Howard Hughes Medical Institute
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

use MediaWiki\Auth\AbstractPasswordPrimaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Auth\PasswordAuthenticationRequest;
use MediaWiki\Auth\RememberMeAuthenticationRequest;
use MediaWiki\Auth\UserDataAuthenticationRequest;
use MediaWiki\MediaWikiServices;
use MediaWiki\Session\UserInfo;


/**
 * Helper: make an HTTP request to the WordPress REST API.
 *
 * When AuthWPApiUrl is configured (cross-server mode), all WordPress
 * interactions go through the AuthWP REST Bridge plugin.  When it is
 * empty, the extension falls back to loading wp-load.php locally
 * (original behaviour).
 */
class AuthWPRestClient {

    /** @var string|null Cached API URL */
    private static $apiUrl = null;

    /** @var string|null Cached shared secret */
    private static $apiSecret = null;

    /** @var bool|null Whether we are in REST mode */
    private static $restMode = null;

    /**
     * Determine whether we are operating in REST (cross-server) mode.
     */
    public static function isRestMode() {
        if ( self::$restMode === null ) {
            $config = MediaWikiServices::getInstance()
                ->getConfigFactory()
                ->makeConfig( 'AuthWP' );
            self::$apiUrl    = $config->get( 'AuthWPApiUrl' );
            self::$apiSecret = $config->get( 'AuthWPApiSecret' );
            self::$restMode  = !empty( self::$apiUrl );
        }
        return self::$restMode;
    }

    /**
     * Make a request to the WordPress REST Bridge.
     *
     * @param string $method  'GET' or 'POST'
     * @param string $endpoint  e.g. '/authenticate'
     * @param array  $body  POST body (will be JSON-encoded)
     * @return array|null  Decoded JSON response, or null on failure
     */
    public static function request( $method, $endpoint, $body = [] ) {
        self::isRestMode(); // ensure config is loaded

        $url = rtrim( self::$apiUrl, '/' ) . $endpoint;

        $options = [
            'method'  => $method,
            'timeout' => 15,
        ];

        $headers = [
            'X-AuthWP-Secret' => self::$apiSecret,
            'Content-Type'    => 'application/json',
            'Accept'          => 'application/json',
        ];

        if ( $method === 'POST' && !empty( $body ) ) {
            $options['postData'] = json_encode( $body );
        }

        $httpFactory = MediaWikiServices::getInstance()->getHttpRequestFactory();
        $req = $httpFactory->create( $url, $options, __METHOD__ );

        foreach ( $headers as $k => $v ) {
            $req->setHeader( $k, $v );
        }

        $status = $req->execute();
        if ( !$status->isOK() ) {
            wfLogWarning( 'AuthWP REST request failed: ' . $status->getMessage()->text() );
            return null;
        }

        return json_decode( $req->getContent(), true );
    }

    /**
     * POST /authenticate — validate credentials.
     */
    public static function authenticate( $username, $password ) {
        return self::request( 'POST', '/authenticate', [
            'username' => $username,
            'password' => $password,
        ] );
    }

    /**
     * GET /user-exists?login=<username or email>
     *
     * Uses a query parameter instead of a URL path segment to avoid
     * regex issues with characters like @ in email addresses.
     *
     * @return array|false  Array with 'exists' and 'user_login' keys, or false
     */
    public static function userExists( $username ) {
        $result = self::request( 'GET', '/user-exists?login=' . rawurlencode( $username ) );
        if ( $result === null ) {
            // Transport-level failure (bridge unreachable, bad secret,
            // non-JSON response).  Distinct from "user does not exist" so
            // callers can report a meaningful error.
            return null;
        }
        if ( !empty( $result['exists'] ) ) {
            return $result;
        }
        return false;
    }

    /**
     * GET /user?login=<username or email>
     */
    public static function getUser( $username ) {
        $result = self::request( 'GET', '/user?login=' . rawurlencode( $username ) );
        if ( $result && !empty( $result['found'] ) ) {
            return $result['user'];
        }
        return null;
    }

    /**
     * POST /change-password
     */
    public static function changePassword( $username, $password ) {
        return self::request( 'POST', '/change-password', [
            'username' => $username,
            'password' => $password,
        ] );
    }

    /**
     * POST /sso-exchange — redeem a one-time SSO code for an identity.
     *
     * Used by the redirect flow, where the user has already authenticated
     * (password + 2FA) on WordPress's own login form. No credentials are
     * sent here; the code is a short-lived, single-use bearer token that
     * WordPress minted for an already-established session.
     *
     * @param string $code  One-time code returned via the browser redirect
     * @param string $state Opaque value we generated, echoed back by WordPress
     * @return array|null   ['authenticated'=>bool,'user'=>[...]] or null on
     *                      transport failure (bridge unreachable / bad secret)
     */
    public static function ssoExchange( $code, $state ) {
        return self::request( 'POST', '/sso-exchange', [
            'code'  => $code,
            'state' => $state,
        ] );
    }

    /**
     * Base URL of the WordPress site for starting the SSO redirect flow.
     * Falls back to deriving the site root from the REST API URL, so an
     * existing install does not have to set a second constant.
     *
     * @return string|null
     */
    public static function ssoStartUrl() {
        $config = MediaWikiServices::getInstance()
            ->getConfigFactory()->makeConfig( 'AuthWP' );

        if ( $config->has( 'AuthWPSSOStartUrl' ) ) {
            $explicit = $config->get( 'AuthWPSSOStartUrl' );
            if ( $explicit ) {
                return $explicit;
            }
        }

        // Derive: https://site/wp-json/authwp/v1  ->  https://site/
        self::isRestMode();
        if ( !self::$apiUrl ) {
            return null;
        }
        $pos = strpos( self::$apiUrl, '/wp-json' );
        return $pos === false
            ? null
            : substr( self::$apiUrl, 0, $pos ) . '/';
    }
}


// ---------- LOCAL MODE ONLY ----------
// Bootstrap WordPress when running on the same server.
if ( !AuthWPRestClient::isRestMode() ) {
    $WP_relpath = MediaWikiServices::getInstance()
        ->getConfigFactory()
        ->makeConfig( 'AuthWP' )
        ->get( 'AuthWPPath' );
    require_once $WP_relpath . DIRECTORY_SEPARATOR . 'wp-load.php';
}


class AuthWPAuthenticationProvider extends
    AbstractPasswordPrimaryAuthenticationProvider {

    /**
     * Cache the WordPress roles from the most recent successful authentication
     * so postAuthentication() can sync MediaWiki groups.
     * @var array|null
     */
    private static $lastAuthRoles = null;

    /**
     * Cache the real WordPress username (as stored in wp_users.user_login)
     * from the most recent successful authentication.
     *
     * MediaWiki's User::getCanonicalName() mangles usernames via
     * Title::makeTitleSafe(), which converts underscores to spaces,
     * capitalises the first letter, collapses consecutive spaces, and
     * trims leading/trailing whitespace.  This means a WP user like
     * "wpuser_87" becomes "Wpuser 87" in MW — which then fails the
     * REST lookup back to WordPress.
     *
     * By caching the actual WP username here during beginPrimaryAuthentication()
     * we can pass the correct value to testUserForCreation() later.
     *
     * @var string|null
     */
    private static $lastAuthWpUsername = null;

    private function is_role_allowed_from_roles( array $roles ) {
        // Delegates to the static implementation so the password path and the
        // SSO path can never apply different role policy.
        return self::isRoleAllowedFromRoles( $roles );
    }

    private function is_role_allowed( $wp_user ) {
        return $this->is_role_allowed_from_roles( (array)$wp_user->roles );
    }

    /* ------------------------------------------------------------------ */
    /*  Accessors for the SSO redirect provider                            */
    /*                                                                     */
    /*  AuthWPSSOProvider is a separate provider but must apply exactly the */
    /*  same role policy, rename mapping and group-sync as the password     */
    /*  path. These expose that logic rather than duplicating it, so the    */
    /*  two entry points cannot drift apart.                                */
    /* ------------------------------------------------------------------ */

    /**
     * Static form of the role check, for callers without an instance.
     * @param array $roles WordPress role slugs
     * @return bool
     */
    public static function isRoleAllowedFromRoles( array $roles ) {
        $allowedRoles = MediaWikiServices::getInstance()
            ->getConfigFactory()
            ->makeConfig( 'AuthWP' )
            ->get( 'AuthWPAllowedRoles' );

        if ( !$allowedRoles || !is_array( $allowedRoles ) ) {
            return true;
        }

        return (bool)array_intersect( (array)$allowedRoles, $roles );
    }

    /**
     * Public wrapper around the renamed-user mapping.
     * @param string $wpUsername
     * @return string MediaWiki username to log in as
     */
    public static function resolveRenamedUserPublic( $wpUsername ) {
        return self::resolveRenamedUser( $wpUsername );
    }

    /**
     * Seed the caches that postAuthentication() and testUserForCreation()
     * read, so an SSO login syncs groups and auto-creates accounts using the
     * same code path as a password login.
     *
     * @param string $wpUsername Resolved WordPress login
     * @param array  $roles      WordPress role slugs
     */
    public static function rememberSsoContext( $wpUsername, array $roles ) {
        self::$lastAuthWpUsername = $wpUsername;
        self::$lastAuthRoles      = $roles;
    }

    public function accountCreationType() {
        return self::TYPE_CREATE;
    }

    public function beginPrimaryAccountCreation(
        $user, $creator, array $reqs ) {
        return AuthenticationResponse::newFail(
            wfMessage( 'authwp-registration-disabled' )
        );
    }

    public function beginPrimaryAuthentication ( array $reqs ) {
        $req_password = AuthenticationRequest::getRequestByClass(
            $reqs, PasswordAuthenticationRequest::class );
        if ( $req_password &&
            $req_password->username !== null &&
            $req_password->password !== null ) {

            // ---- REST MODE (cross-server) ----
            if ( AuthWPRestClient::isRestMode() ) {
                wfDebugLog( 'AuthWP', "beginPrimaryAuthentication: REST mode, input username='{$req_password->username}'" );

                $existsResult = AuthWPRestClient::userExists( $req_password->username );
                wfDebugLog( 'AuthWP', 'beginPrimaryAuthentication: userExists result=' . json_encode( $existsResult ) );

                if ( $existsResult === null ) {
                    // The REST bridge could not be reached.  Do not fall
                    // through to auto-creation: that surfaces as the
                    // misleading "No matching WordPress account found".
                    return AuthenticationResponse::newFail(
                        wfMessage( 'authwp-bridge-error' ) );
                }

                if ( $existsResult ) {
                    // Use the resolved WordPress username (handles email→username mapping).
                    // This ensures the MW account is created as "Chris", not "chris@example.com".
                    $wpUsername = $existsResult['user_login'] ?? $req_password->username;
                    wfDebugLog( 'AuthWP', "beginPrimaryAuthentication: resolved WP username='$wpUsername'" );

                    $result = AuthWPRestClient::authenticate(
                        $req_password->username,
                        $req_password->password
                    );

                    if ( !$result || empty( $result['authenticated'] ) ) {
                        wfDebugLog( 'AuthWP', 'beginPrimaryAuthentication: authentication FAILED' );
                        return $this->failResponse( $req_password );
                    }

                    $roles = $result['user']['roles'] ?? [];
                    wfDebugLog( 'AuthWP', 'beginPrimaryAuthentication: authenticated OK, roles=' . json_encode( $roles ) );

                    if ( !$this->is_role_allowed_from_roles( $roles ) ) {
                        return AuthenticationResponse::newFail(
                            wfMessage( 'authwp-staff-only' )
                        );
                    }

                    // Cache roles for postAuthentication() to sync MW groups
                    self::$lastAuthRoles = $roles;

                    // Cache the real WP username so testUserForCreation()
                    // can look up the WP account using the correct identifier,
                    // not the MW-canonicalized version (which mangles underscores,
                    // capitalisation, etc.).
                    self::$lastAuthWpUsername = $wpUsername;

                    // Check if a MW user was renamed but still maps to this WP username.
                    // If so, log them into the renamed account instead of the WP username.
                    $mwUsername = self::resolveRenamedUser( $wpUsername );
                    wfDebugLog( 'AuthWP', "beginPrimaryAuthentication: resolveRenamedUser('$wpUsername') => '$mwUsername'" );

                    // Pass the resolved username (renamed or original WP username)
                    wfDebugLog( 'AuthWP', "beginPrimaryAuthentication: returning newPass('$mwUsername')" );
                    return AuthenticationResponse::newPass( $mwUsername );

                } elseif ( UserInfo::newFromName( $req_password->username )
                    ->getId() !== 0 ) {
                    wfDebugLog( 'AuthWP', "beginPrimaryAuthentication: WP user not found, but MW user exists — abstaining" );
                    return AuthenticationResponse::newAbstain();
                }

                wfDebugLog( 'AuthWP', "beginPrimaryAuthentication: REST mode fallthrough (WP user not found, no MW user)" );

                // Unknown to both WordPress and MediaWiki.  Fail here with
                // a helpful message rather than falling through to
                // newPass(), which bounces off auto-creation with a
                // confusing "No matching WordPress account found" error.
                return AuthenticationResponse::newFail(
                    wfMessage( 'authwp-unknown-user' ) );

            // ---- LOCAL MODE (same server) ----
            } else {
                if ( username_exists( $req_password->username ) ) {
                    $creds = [
                        'user_login'    => $req_password->username,
                        'user_password' => $req_password->password
                    ];

                    $req_rememberMe = AuthenticationRequest::getRequestByClass(
                        $reqs, RememberMeAuthenticationRequest::class );
                    if ( $req_rememberMe ) {
                        $creds[ 'remember' ] = $req_rememberMe->rememberMe;
                    }

                    if ( is_wp_error( wp_signon( $creds, true ) ) ) {
                        return $this->failResponse( $req_password );
                    }

                    $wp_user = wp_get_current_user();
                    if ( !$wp_user || !$wp_user->exists() || !$this->is_role_allowed( $wp_user ) ) {
                        wp_logout();
                        return AuthenticationResponse::newFail(
                            wfMessage( 'authwp-staff-only' )
                        );
                    }

                    // Cache roles for postAuthentication() to sync MW groups
                    self::$lastAuthRoles = (array)$wp_user->roles;

                    return AuthenticationResponse::newPass(
                        $req_password->username );

                } elseif ( UserInfo::newFromName( $req_password->username )
                    ->getId() !== 0) {
                    return AuthenticationResponse::newAbstain();
                }

                // Unknown to both WordPress and MediaWiki (see REST branch).
                return AuthenticationResponse::newFail(
                    wfMessage( 'authwp-unknown-user' ) );
            }
        }

        return AuthenticationResponse::newPass(
            $req_password->username );
    }


    /**
     * Called after a successful login. Syncs MediaWiki groups based on
     * the user's WordPress roles using $wgAuthWPRoleMap.
     *
     * Example config in LocalSettings.php:
     *   $wgAuthWPRoleMap = [
     *       'administrator' => [ 'sysop', 'bureaucrat' ],
     *       'editor'        => [ 'editor' ],
     *       'volunteer'     => [ 'volunteer' ],
     *   ];
     */
    public function postAuthentication( $user, AuthenticationResponse $response ) {
        if ( $response->status !== AuthenticationResponse::PASS ) {
            return;
        }

        $wpRoles = self::$lastAuthRoles;
        if ( $wpRoles === null ) {
            return;
        }
        self::$lastAuthRoles = null; // clear cache

        $config = MediaWikiServices::getInstance()
            ->getConfigFactory()
            ->makeConfig( 'AuthWP' );

        $roleMap = $config->get( 'AuthWPRoleMap' );
        if ( !$roleMap || !is_array( $roleMap ) ) {
            return;
        }

        $userGroupManager = MediaWikiServices::getInstance()->getUserGroupManager();
        $currentGroups = $userGroupManager->getUserGroups( $user );

        // Collect all MW groups that are managed by the role map
        $managedGroups = [];
        foreach ( $roleMap as $wpRole => $mwGroups ) {
            foreach ( (array)$mwGroups as $g ) {
                $managedGroups[$g] = true;
            }
        }

        // Determine which MW groups the user should have based on their WP roles
        $desiredGroups = [];
        foreach ( $wpRoles as $wpRole ) {
            if ( isset( $roleMap[$wpRole] ) ) {
                foreach ( (array)$roleMap[$wpRole] as $g ) {
                    $desiredGroups[$g] = true;
                }
            }
        }

        // Add groups the user should have but doesn't
        foreach ( $desiredGroups as $group => $_ ) {
            if ( !in_array( $group, $currentGroups ) ) {
                $userGroupManager->addUserToGroup( $user, $group );
                wfDebugLog( 'authentication', "AuthWP: added group '$group' to user '{$user->getName()}'" );
            }
        }

        // Remove managed groups the user has but shouldn't
        foreach ( $currentGroups as $group ) {
            if ( isset( $managedGroups[$group] ) && !isset( $desiredGroups[$group] ) ) {
                $userGroupManager->removeUserFromGroup( $user, $group );
                wfDebugLog( 'authentication', "AuthWP: removed group '$group' from user '{$user->getName()}'" );
            }
        }
    }


    /**
     * Look up whether a MW user was renamed from a given WP username.
     * Checks the 'authwp-wp-username' user option set during approved renames.
     *
     * @param string $wpUsername  The WordPress username returned by the REST API
     * @return string  The current MW username (may differ if user was renamed)
     */
    private static function resolveRenamedUser( $wpUsername ) {
        $dbr = MediaWikiServices::getInstance()->getDBLoadBalancer()->getConnection( DB_REPLICA );

        // Normalize to lowercase — WordPress user_login is always lowercase,
        // and user_properties.up_value is varbinary (case-sensitive).
        $wpUsernameLower = strtolower( $wpUsername );

        $row = $dbr->selectRow(
            [ 'user_properties', 'user' ],
            [ 'user_name' ],
            [
                'up_property' => 'authwp-wp-username',
                'up_value'    => $wpUsernameLower,
            ],
            __METHOD__,
            [],
            [
                'user' => [ 'INNER JOIN', 'user_id = up_user' ],
            ]
        );

        if ( $row ) {
            wfDebugLog( 'AuthWP',
                "Resolved WP username '$wpUsername' to renamed MW user '{$row->user_name}'" );
            return $row->user_name;
        }

        return $wpUsername;
    }


    public function providerAllowsAuthenticationDataChange(
        AuthenticationRequest $req, $checkData = true ) {

        if ( $req->action === AuthManager::ACTION_REMOVE ) {
            return \StatusValue::newGood( 'ignored' );
        }
        return \StatusValue::newGood();
    }


    public function providerAllowsPropertyChange( $property ) {
        return false;
    }


    public function providerChangeAuthenticationData(
        AuthenticationRequest $req ) {

        if ( AuthWPRestClient::isRestMode() ) {
            // Cross-server: use REST API to change password
            if ( $req->action === AuthManager::ACTION_CHANGE ) {
                AuthWPRestClient::changePassword(
                    $req->username, $req->password );
            }
        } else {
            // Local: use WordPress functions directly
            $wp_user = get_user_by( 'login', $req->username );
            if ( $wp_user ) {
                if ( $req->action === AuthManager::ACTION_CHANGE ) {
                    wp_update_user( [
                        'ID'        => $wp_user->ID,
                        'user_pass' => $req->password
                    ] );
                }
            }
        }
    }


    public function testUserExists( $username, $flags = User::READ_NORMAL ) {
        if ( AuthWPRestClient::isRestMode() ) {
            // is_array(): treat transport failure (null) as "does not
            // exist" rather than accidentally reporting true.
            return is_array( AuthWPRestClient::userExists( $username ) );
        }
        return username_exists( $username );
    }


    public function testUserForCreation(
        $user, $autocreate, array $options = [] ) {

        if ( $autocreate ) {
            if ( AuthWPRestClient::isRestMode() ) {
                // Prefer the real WP username cached during authentication.
                //
                // MediaWiki's User::getCanonicalName() transforms usernames
                // via Title::makeTitleSafe(), which:
                //   - converts underscores to spaces
                //   - capitalises the first letter
                //   - collapses consecutive spaces
                //   - trims leading/trailing whitespace
                //
                // This means a WP user like "wpuser_87" becomes "Wpuser 87"
                // in $user->getName(), which would then fail the REST lookup
                // back to WordPress.  Using the cached WP username avoids
                // this entirely.
                $lookupName = self::$lastAuthWpUsername ?? $user->getName();
                self::$lastAuthWpUsername = null; // clear cache

                wfDebugLog( 'AuthWP',
                    "testUserForCreation: MW name='{$user->getName()}', "
                    . "WP lookup name='$lookupName'" );

                $wp_user_data = AuthWPRestClient::getUser( $lookupName );
                if ( !$wp_user_data ) {
                    return \StatusValue::newFatal(
                        wfMessage( 'authwp-no-wordpress-user' ) );
                }
                $user->setEmail( $wp_user_data['user_email'] );
                $user->setRealName( $wp_user_data['display_name'] );
            } else {
                // Local mode: try the cached WP username first, fall back
                // to the MW-canonicalized name.
                $lookupName = self::$lastAuthWpUsername ?? $user->getName();
                self::$lastAuthWpUsername = null;

                $wp_user = get_user_by( 'login', $lookupName );
                if ( !$wp_user ) {
                    // Last resort: try the MW-canonicalized name
                    $wp_user = get_user_by( 'login', $user->getName() );
                }
                if ( !$wp_user ) {
                    return \StatusValue::newFatal(
                        wfMessage( 'authwp-no-wordpress-user' ) );
                }
                $user->setEmail( $wp_user->user_email );
                $user->setRealName( $wp_user->display_name );
            }
        }

        return \StatusValue::newGood();
    }
}
