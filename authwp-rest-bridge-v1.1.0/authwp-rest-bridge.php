<?php
/**
 * Plugin Name: AuthWP REST Bridge
 * Plugin URI:  https://github.com/Menhirs-Fate/AuthWP
 * Description: Exposes WordPress authentication as a REST API for remote
 *              MediaWiki AuthWP integration. Secured with a shared secret.
 * Version:     1.2.0
 * Author:      Dan Boyes - Tawa Group
 * License:     MIT
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

/**
 * Configuration (all defined in wp-config.php):
 *
 *   // Required. Must match $wgAuthWPApiSecret in MediaWiki's LocalSettings.php.
 *   define( 'AUTHWP_REST_SECRET', 'your-long-random-string-here' );
 *
 *   // Recommended. Restrict every route to the wiki server's IP(s).
 *   // Accepts a single IP, a comma-separated string, or an array. CIDR
 *   // ranges (e.g. '10.0.0.0/24') are supported for IPv4 and IPv6.
 *   // If left undefined, IP filtering is disabled (backward compatible).
 *   define( 'AUTHWP_ALLOWED_IPS', '203.0.113.10' );
 *
 *   // Only set to true if WordPress sits behind a trusted reverse proxy
 *   // that appends the real client IP to X-Forwarded-For AND strips any
 *   // inbound XFF from untrusted clients. Otherwise leave undefined:
 *   // REMOTE_ADDR is the only value a remote client cannot spoof.
 *   // define( 'AUTHWP_TRUST_XFF', true );
 *
 *   // Set to false to disable remote password changes entirely.
 *   // Defaults to enabled. Privileged accounts (admins) are ALWAYS
 *   // refused regardless of this setting.
 *   // define( 'AUTHWP_ALLOW_PASSWORD_CHANGE', false );
 *
 *   // Optional. Roles whose passwords may never be changed via the bridge.
 *   // Capability checks (manage_options / edit_users / promote_users)
 *   // already block admin-like roles; this is an extra explicit deny-list.
 *   // define( 'AUTHWP_PROTECTED_ROLES', [ 'administrator', 'shop_manager' ] );
 */

class AuthWP_REST_Bridge {

    const NAMESPACE_V1 = 'authwp/v1';

    public function __construct() {
        add_action( 'rest_api_init', [ $this, 'register_routes' ] );
    }

    /* ------------------------------------------------------------------ */
    /*  Route registration                                                */
    /* ------------------------------------------------------------------ */

    public function register_routes() {

        // POST /wp-json/authwp/v1/authenticate
        register_rest_route( self::NAMESPACE_V1, '/authenticate', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'handle_authenticate' ],
            'permission_callback' => [ $this, 'verify_secret' ],
        ] );

        // GET /wp-json/authwp/v1/user-exists?login=<username or email>
        // Uses a query parameter to avoid regex issues with @ . - etc.
        register_rest_route( self::NAMESPACE_V1, '/user-exists', [
            'methods'             => 'GET',
            'callback'            => [ $this, 'handle_user_exists' ],
            'permission_callback' => [ $this, 'verify_secret' ],
        ] );

        // GET /wp-json/authwp/v1/user?login=<username or email>
        register_rest_route( self::NAMESPACE_V1, '/user', [
            'methods'             => 'GET',
            'callback'            => [ $this, 'handle_get_user' ],
            'permission_callback' => [ $this, 'verify_secret' ],
        ] );

        // POST /wp-json/authwp/v1/change-password
        register_rest_route( self::NAMESPACE_V1, '/change-password', [
            'methods'             => 'POST',
            'callback'            => [ $this, 'handle_change_password' ],
            'permission_callback' => [ $this, 'verify_secret' ],
        ] );
    }

    /* ------------------------------------------------------------------ */
    /*  Shared-secret verification                                        */
    /* ------------------------------------------------------------------ */

    /**
     * Every request must include the header:
     *   X-AuthWP-Secret: <shared secret>
     */
    public function verify_secret( WP_REST_Request $request ) {
        // IP allow-list is checked first so that callers outside the
        // permitted range learn nothing about the bridge's configuration
        // state (see the 500-vs-403 distinction below).
        if ( ! $this->is_ip_allowed() ) {
            $this->log( 'request rejected: client IP "'
                . $this->get_client_ip() . '" not in AUTHWP_ALLOWED_IPS' );
            return new WP_Error(
                'authwp_forbidden_ip',
                'Client IP not permitted.',
                [ 'status' => 403 ]
            );
        }

        $secret = defined( 'AUTHWP_REST_SECRET' ) ? AUTHWP_REST_SECRET : '';
        if ( empty( $secret ) ) {
            return new WP_Error(
                'authwp_not_configured',
                'AUTHWP_REST_SECRET is not defined in wp-config.php.',
                [ 'status' => 500 ]
            );
        }

        $provided = $request->get_header( 'X-AuthWP-Secret' );
        if ( ! hash_equals( $secret, (string) $provided ) ) {
            return new WP_Error(
                'authwp_forbidden',
                'Invalid or missing X-AuthWP-Secret header.',
                [ 'status' => 403 ]
            );
        }

        return true;
    }

    /* ------------------------------------------------------------------ */
    /*  POST /authenticate                                                */
    /* ------------------------------------------------------------------ */

    /**
     * Expects JSON body: { "username": "...", "password": "..." }
     *
     * Authentication strategy:
     *  1. Resolve the identifier (username or email) to a WP_User.
     *  2. Try WordPress Application Passwords first — these bypass 2FA
     *     and are the recommended approach for service-to-service auth.
     *  3. Fall back to regular wp_authenticate() for sites without 2FA.
     */
    public function handle_authenticate( WP_REST_Request $request ) {
        $identifier = sanitize_user( $request->get_param( 'username' ) );
        $password   = $request->get_param( 'password' );

        if ( empty( $identifier ) || empty( $password ) ) {
            return new WP_Error(
                'authwp_missing_credentials',
                'Username and password are required.',
                [ 'status' => 400 ]
            );
        }

        // Resolve email to username if needed
        $resolved = $this->resolve_user( $identifier );
        $username = $resolved ? $resolved->user_login : $identifier;

        // Strategy 1: Try Application Password authentication
        $app_auth = $this->try_application_password( $username, $password );
        if ( $app_auth !== null ) {
            return $app_auth;
        }

        // Strategy 2: Fall back to regular wp_authenticate
        $user = wp_authenticate( $username, $password );

        if ( is_wp_error( $user ) ) {
            return new WP_REST_Response( [
                'authenticated' => false,
                'error'         => $user->get_error_message(),
            ], 401 );
        }

        return new WP_REST_Response( [
            'authenticated' => true,
            'user'          => $this->format_user( $user ),
        ], 200 );
    }

    /**
     * Attempt to authenticate using WordPress Application Passwords.
     * Returns a WP_REST_Response on success, or null if the password
     * is not a valid application password (so caller can fall back).
     */
    private function try_application_password( $username, $password ) {
        // Application Passwords require WP 5.6+
        if ( ! function_exists( 'wp_authenticate_application_password' ) ) {
            return null;
        }

        $user = get_user_by( 'login', $username );
        if ( ! $user ) {
            return null;
        }

        // wp_authenticate_application_password returns WP_User on success,
        // WP_Error on failure, or null if the password isn't an app password.
        //
        // SECURITY: the first argument ($input_user) MUST be null.  WordPress
        // core short-circuits and returns $input_user unchanged if it is
        // already a WP_User — so passing the resolved $user here bypasses the
        // password check entirely and authenticates ANY password.
        $result = wp_authenticate_application_password( null, $username, $password );

        if ( $result instanceof WP_User ) {
            return new WP_REST_Response( [
                'authenticated' => true,
                'user'          => $this->format_user( $result ),
            ], 200 );
        }

        // Not an application password — return null to fall back
        return null;
    }

    /* ------------------------------------------------------------------ */
    /*  GET /user-exists/<username>                                       */
    /* ------------------------------------------------------------------ */

    public function handle_user_exists( WP_REST_Request $request ) {
        $identifier = sanitize_user( $request->get_param( 'login' ) );
        if ( empty( $identifier ) ) {
            // Backwards compat: also check 'username' param
            $identifier = sanitize_user( $request->get_param( 'username' ) );
        }
        $user = $this->resolve_user( $identifier );

        return new WP_REST_Response( [
            'exists'     => $user !== false,
            'user_login' => $user ? $user->user_login : null,
        ], 200 );
    }

    /* ------------------------------------------------------------------ */
    /*  GET /user/<username>                                              */
    /* ------------------------------------------------------------------ */

    public function handle_get_user( WP_REST_Request $request ) {
        $identifier = sanitize_user( $request->get_param( 'login' ) );
        if ( empty( $identifier ) ) {
            $identifier = sanitize_user( $request->get_param( 'username' ) );
        }
        $wp_user = $this->resolve_user( $identifier );

        if ( ! $wp_user ) {
            return new WP_REST_Response( [
                'found' => false,
            ], 404 );
        }

        return new WP_REST_Response( [
            'found' => true,
            'user'  => $this->format_user( $wp_user ),
        ], 200 );
    }

    /* ------------------------------------------------------------------ */
    /*  POST /change-password                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Expects JSON body: { "username": "...", "password": "..." }
     */
    public function handle_change_password( WP_REST_Request $request ) {
        // Master switch. Remote password change is enabled by default to
        // preserve existing behaviour, but can be turned off entirely.
        $enabled = defined( 'AUTHWP_ALLOW_PASSWORD_CHANGE' )
            ? (bool) AUTHWP_ALLOW_PASSWORD_CHANGE
            : true;
        if ( ! $enabled ) {
            $this->log( 'change-password: refused (feature disabled)' );
            return new WP_REST_Response( [
                'success' => false,
                'error'   => 'Password change through the bridge is disabled.',
            ], 403 );
        }

        $username = sanitize_user( $request->get_param( 'username' ) );
        $password = $request->get_param( 'password' );

        if ( empty( $username ) || empty( $password ) ) {
            return new WP_REST_Response( [
                'success' => false,
                'error'   => 'Username and password are required.',
            ], 400 );
        }

        $wp_user = $this->resolve_user( $username );
        if ( ! $wp_user ) {
            return new WP_REST_Response( [
                'success' => false,
                'error'   => 'User not found.',
            ], 404 );
        }

        // Never allow a privileged account's password to be changed
        // remotely. This is the key mitigation: even with the shared
        // secret, an attacker cannot reset an administrator's password.
        if ( $this->is_protected_user( $wp_user ) ) {
            $this->log( sprintf(
                'change-password: REFUSED for privileged user "%s" (id %d, roles: %s)',
                $wp_user->user_login,
                $wp_user->ID,
                implode( ',', (array) $wp_user->roles )
            ) );
            return new WP_REST_Response( [
                'success' => false,
                'error'   => 'This account is not permitted to change its password through the bridge.',
            ], 403 );
        }

        wp_set_password( $password, $wp_user->ID );
        $this->log( sprintf(
            'change-password: changed for "%s" (id %d)',
            $wp_user->user_login,
            $wp_user->ID
        ) );

        return new WP_REST_Response( [
            'success' => true,
        ], 200 );
    }

    /* ------------------------------------------------------------------ */
    /*  Helpers                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Resolve a username OR email address to a WP_User object.
     * WordPress allows login by email, so we support both.
     *
     * MediaWiki's username canonicalization (Title::makeTitleSafe) transforms
     * usernames before they reach the REST API:
     *   - underscores (_) become spaces
     *   - first letter is capitalised
     *   - consecutive spaces are collapsed
     *   - leading/trailing whitespace is trimmed
     *
     * This means a WP user "wpuser_87" arrives here as "Wpuser 87".
     * The fallback lookups below handle these transformations.
     */
    private function resolve_user( $identifier ) {
        // 1. Exact match by login name (fastest path)
        $user = get_user_by( 'login', $identifier );
        if ( $user ) {
            return $user;
        }

        // 2. Try by email
        if ( is_email( $identifier ) ) {
            $user = get_user_by( 'email', $identifier );
            if ( $user ) {
                return $user;
            }
        }

        // 3. Case-insensitive login lookup.
        //    Handles: "Chris" vs "chris" (MW capitalises first letter)
        global $wpdb;
        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT ID FROM {$wpdb->users} WHERE LOWER(user_login) = LOWER(%s) LIMIT 1",
            $identifier
        ) );
        if ( $row ) {
            return get_user_by( 'id', $row->ID );
        }

        // 4. Normalised lookup: treat underscores and spaces as equivalent.
        //    Handles MW's underscore→space conversion.
        //
        //    Both sides are normalised: underscores replaced with spaces,
        //    consecutive spaces collapsed (two REPLACE passes covers up to
        //    4 consecutive underscores/spaces → 1 space), trimmed, lowercased.
        //
        //    Examples this catches:
        //      "Wpuser 87"  matches WP "wpuser_87"  (space↔underscore + case)
        //      "Some user"  matches WP "some__user"  (collapsed double underscore)
        //      "Leading"    matches WP "_leading"    (leading underscore trimmed)
        //      "A b c d"    matches WP "a_b_c_d"    (multiple underscores)
        $row = $wpdb->get_row( $wpdb->prepare(
            "SELECT ID FROM {$wpdb->users}
             WHERE TRIM(REPLACE(REPLACE(LOWER(REPLACE(user_login, '_', ' ')), '  ', ' '), '  ', ' '))
                 = TRIM(REPLACE(REPLACE(LOWER(REPLACE(%s, '_', ' ')), '  ', ' '), '  ', ' '))
             LIMIT 1",
            $identifier
        ) );
        if ( $row ) {
            return get_user_by( 'id', $row->ID );
        }

        // 5. Last resort: try replacing spaces back to underscores.
        //    Catches any edge cases where the SQL normalisation above
        //    might miss due to encoding differences.
        $underscored = str_replace( ' ', '_', $identifier );
        if ( $underscored !== $identifier ) {
            $user = get_user_by( 'login', strtolower( $underscored ) );
            if ( $user ) {
                return $user;
            }
        }

        return false;
    }

    private function format_user( WP_User $user ) {
        return [
            'ID'           => $user->ID,
            'user_login'   => $user->user_login,
            'user_email'   => $user->user_email,
            'display_name' => $user->display_name,
            'roles'        => (array) $user->roles,
        ];
    }

    /* ------------------------------------------------------------------ */
    /*  IP allow-list                                                     */
    /* ------------------------------------------------------------------ */

    /**
     * True if the request's client IP is permitted, or if no allow-list
     * is configured (backward compatible — filtering is opt-in).
     */
    private function is_ip_allowed() {
        if ( ! defined( 'AUTHWP_ALLOWED_IPS' ) || empty( AUTHWP_ALLOWED_IPS ) ) {
            return true;
        }

        $allowed = AUTHWP_ALLOWED_IPS;
        if ( is_string( $allowed ) ) {
            $allowed = array_map( 'trim', explode( ',', $allowed ) );
        }

        $client = $this->get_client_ip();
        if ( $client === '' ) {
            return false;
        }

        foreach ( (array) $allowed as $entry ) {
            if ( $this->ip_matches( $client, $entry ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determine the client IP.  REMOTE_ADDR is the only value a remote
     * client cannot spoof, so it is used by default.  X-Forwarded-For is
     * consulted only when AUTHWP_TRUST_XFF is set, for installs behind a
     * trusted reverse proxy that appends (and sanitises) the header.
     */
    private function get_client_ip() {
        if ( defined( 'AUTHWP_TRUST_XFF' ) && AUTHWP_TRUST_XFF
            && ! empty( $_SERVER['HTTP_X_FORWARDED_FOR'] ) ) {
            $parts = explode( ',', $_SERVER['HTTP_X_FORWARDED_FOR'] );
            // Rightmost entry = address seen by the nearest trusted proxy.
            return trim( end( $parts ) );
        }
        return isset( $_SERVER['REMOTE_ADDR'] ) ? $_SERVER['REMOTE_ADDR'] : '';
    }

    /**
     * Match an IP against an exact address or a CIDR range (IPv4/IPv6).
     */
    private function ip_matches( $ip, $range ) {
        $range = trim( $range );
        if ( $range === '' ) {
            return false;
        }

        // Exact match (no CIDR suffix).
        if ( strpos( $range, '/' ) === false ) {
            return $ip === $range;
        }

        list( $subnet, $bits ) = explode( '/', $range, 2 );
        $bits = (int) $bits;

        $ipBin     = @inet_pton( $ip );
        $subnetBin = @inet_pton( $subnet );
        if ( $ipBin === false || $subnetBin === false
            || strlen( $ipBin ) !== strlen( $subnetBin ) ) {
            // Mixing IPv4 and IPv6, or an unparseable value.
            return false;
        }

        $wholeBytes = intdiv( $bits, 8 );
        $remainder  = $bits % 8;

        if ( $wholeBytes > 0
            && substr( $ipBin, 0, $wholeBytes ) !== substr( $subnetBin, 0, $wholeBytes ) ) {
            return false;
        }

        if ( $remainder > 0 ) {
            $mask = chr( ( 0xff << ( 8 - $remainder ) ) & 0xff );
            if ( ( ord( $ipBin[ $wholeBytes ] ) & ord( $mask ) )
                !== ( ord( $subnetBin[ $wholeBytes ] ) & ord( $mask ) ) ) {
                return false;
            }
        }

        return true;
    }

    /* ------------------------------------------------------------------ */
    /*  Privileged-account protection                                     */
    /* ------------------------------------------------------------------ */

    /**
     * True for accounts whose password must never be changed remotely.
     * Capability checks cover administrators and any custom admin-like
     * role; an optional explicit deny-list can be added via
     * AUTHWP_PROTECTED_ROLES.
     */
    private function is_protected_user( WP_User $user ) {
        if ( user_can( $user, 'manage_options' )
            || user_can( $user, 'edit_users' )
            || user_can( $user, 'promote_users' ) ) {
            return true;
        }

        $protectedRoles = defined( 'AUTHWP_PROTECTED_ROLES' )
            ? (array) AUTHWP_PROTECTED_ROLES
            : [ 'administrator', 'super_admin' ];

        return (bool) array_intersect( $protectedRoles, (array) $user->roles );
    }

    /* ------------------------------------------------------------------ */
    /*  Audit logging                                                     */
    /* ------------------------------------------------------------------ */

    private function log( $message ) {
        error_log( '[AuthWP REST Bridge] ' . $message );
    }
}

new AuthWP_REST_Bridge();
