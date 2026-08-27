<?php
/**
 * Schema update hooks for the AuthWP extension.
 */
class AuthWPSchemaHooks {

    /**
     * Add the authwp_rename_requests table during update.php.
     */
    public static function onLoadExtensionSchemaUpdates( $updater ) {
        $dir = dirname( __DIR__ ) . '/sql';

        $updater->addExtensionTable(
            'authwp_rename_requests',
            "$dir/tables.sql"
        );

        return true;
    }
}
