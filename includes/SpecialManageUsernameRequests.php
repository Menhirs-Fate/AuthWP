<?php
/**
 * Special:ManageUsernameRequests — lets sysops review, approve,
 * or deny pending username change requests.
 *
 * Approval triggers MediaWiki's RenameUser and stores the WordPress
 * username mapping so AuthWP can still authenticate the user.
 */

use MediaWiki\MediaWikiServices;

class SpecialManageUsernameRequests extends SpecialPage {

    public function __construct() {
        parent::__construct( 'ManageUsernameRequests', 'renameuser' );
    }

    public function doesWrites() {
        return true;
    }

    public function execute( $par ) {
        $this->checkPermissions();
        $this->checkReadOnly();

        $out = $this->getOutput();
        $out->setPageTitle( $this->msg( 'authwp-rename-manage-title' )->text() );

        $request = $this->getRequest();

        // Handle approve / deny actions
        if ( $request->wasPosted() && $this->getUser()->matchEditToken( $request->getVal( 'wpEditToken' ) ) ) {
            $action = $request->getVal( 'action_type' );
            $requestId = $request->getInt( 'request_id' );
            $adminComment = $request->getVal( 'admin_comment', '' );

            if ( $requestId && in_array( $action, [ 'approve', 'deny' ] ) ) {
                if ( $action === 'approve' ) {
                    $this->approveRequest( $requestId, $adminComment );
                } else {
                    $this->denyRequest( $requestId, $adminComment );
                }
                return;
            }
        }

        // Show pending requests
        $this->showRequests();
    }

    private function showRequests() {
        $out = $this->getOutput();
        $dbr = MediaWikiServices::getInstance()->getDBLoadBalancer()->getConnection( DB_REPLICA );

        // Pending first, then recent resolved
        $rows = $dbr->select(
            'authwp_rename_requests',
            '*',
            [],
            __METHOD__,
            [ 'ORDER BY' => 'aur_status ASC, aur_timestamp DESC', 'LIMIT' => 100 ]
        );

        $pending = [];
        $resolved = [];
        foreach ( $rows as $row ) {
            if ( $row->aur_status === 'pending' ) {
                $pending[] = $row;
            } else {
                $resolved[] = $row;
            }
        }

        if ( !$pending && !$resolved ) {
            $out->addWikiMsg( 'authwp-rename-no-requests' );
            return;
        }

        // Pending requests
        if ( $pending ) {
            $out->addHTML( '<h2>' . $this->msg( 'authwp-rename-pending-header' )->escaped() . '</h2>' );
            foreach ( $pending as $row ) {
                $this->showPendingRow( $row );
            }
        }

        // Resolved requests
        if ( $resolved ) {
            $out->addHTML( '<h2>' . $this->msg( 'authwp-rename-resolved-header' )->escaped() . '</h2>' );
            $out->addHTML( '<table class="wikitable sortable"><thead><tr>' );
            $out->addHTML( '<th>User</th><th>Requested Name</th><th>Status</th><th>Admin</th><th>Comment</th><th>Date</th>' );
            $out->addHTML( '</tr></thead><tbody>' );

            foreach ( $resolved as $row ) {
                $adminUser = $row->aur_admin_id
                    ? MediaWikiServices::getInstance()->getUserFactory()->newFromId( $row->aur_admin_id )
                    : null;
                $adminName = $adminUser ? $adminUser->getName() : '—';
                $statusClass = $row->aur_status === 'approved' ? 'style="color:green"' : 'style="color:red"';

                $out->addHTML( '<tr>' );
                $out->addHTML( '<td>' . htmlspecialchars( $row->aur_old_name ) . '</td>' );
                $out->addHTML( '<td>' . htmlspecialchars( $row->aur_new_name ) . '</td>' );
                $out->addHTML( '<td ' . $statusClass . '>' . htmlspecialchars( $row->aur_status ) . '</td>' );
                $out->addHTML( '<td>' . htmlspecialchars( $adminName ) . '</td>' );
                $out->addHTML( '<td>' . htmlspecialchars( $row->aur_admin_comment ?? '' ) . '</td>' );
                $out->addHTML( '<td>' . htmlspecialchars(
                    $this->getLanguage()->timeanddate( $row->aur_resolved ?? $row->aur_timestamp, true )
                ) . '</td>' );
                $out->addHTML( '</tr>' );
            }

            $out->addHTML( '</tbody></table>' );
        }
    }

    private function showPendingRow( $row ) {
        $out = $this->getOutput();
        $lang = $this->getLanguage();

        $out->addHTML( '<div class="mw-authwp-rename-request" style="border:1px solid #a2a9b1;padding:12px;margin:10px 0;border-radius:4px;">' );
        $out->addHTML( '<strong>' . htmlspecialchars( $row->aur_old_name ) . '</strong>' );
        $out->addHTML( ' &rarr; <strong>' . htmlspecialchars( $row->aur_new_name ) . '</strong>' );
        $out->addHTML( '<br>' . $this->msg( 'authwp-rename-requested-on' )->escaped() . ' '
            . htmlspecialchars( $lang->timeanddate( $row->aur_timestamp, true ) ) );

        if ( $row->aur_reason ) {
            $out->addHTML( '<br>' . $this->msg( 'authwp-rename-reason-label' )->escaped() . ' '
                . htmlspecialchars( $row->aur_reason ) );
        }

        // Approve / Deny form
        $out->addHTML(
            '<form method="post" style="margin-top:8px;">'
            . '<input type="hidden" name="request_id" value="' . (int)$row->aur_id . '">'
            . '<input type="hidden" name="wpEditToken" value="' . htmlspecialchars( $this->getUser()->getEditToken() ) . '">'
            . '<label>' . $this->msg( 'authwp-rename-admin-comment' )->escaped()
            . ' <input type="text" name="admin_comment" size="40"></label> '
            . '<button type="submit" name="action_type" value="approve" style="color:green;font-weight:bold;">'
            . $this->msg( 'authwp-rename-approve' )->escaped() . '</button> '
            . '<button type="submit" name="action_type" value="deny" style="color:red;">'
            . $this->msg( 'authwp-rename-deny' )->escaped() . '</button>'
            . '</form>'
        );

        $out->addHTML( '</div>' );
    }

    private function approveRequest( $requestId, $adminComment ) {
        $out = $this->getOutput();
        $dbw = MediaWikiServices::getInstance()->getDBLoadBalancer()->getConnection( DB_PRIMARY );

        $row = $dbw->selectRow( 'authwp_rename_requests', '*',
            [ 'aur_id' => $requestId, 'aur_status' => 'pending' ], __METHOD__ );

        if ( !$row ) {
            $out->addHTML( '<div class="errorbox">' . $this->msg( 'authwp-rename-not-found' )->escaped() . '</div>' );
            $this->showRequests();
            return;
        }

        $oldName = $row->aur_old_name;
        $newName = $row->aur_new_name;

        // Check RenameUser extension is available
        if ( !class_exists( 'RenameuserSQL' ) ) {
            $out->addHTML( '<div class="errorbox">' . $this->msg( 'authwp-rename-no-renameuser' )->escaped() . '</div>' );
            $this->showRequests();
            return;
        }

        // Look up the user
        $userFactory = MediaWikiServices::getInstance()->getUserFactory();
        $oldUser = $userFactory->newFromName( $oldName );
        if ( !$oldUser || $oldUser->getId() === 0 ) {
            $out->addHTML( '<div class="errorbox">' . $this->msg( 'authwp-rename-user-gone', $oldName )->escaped() . '</div>' );
            $this->showRequests();
            return;
        }

        // Check new name is still available
        $newUser = $userFactory->newFromName( $newName );
        if ( $newUser && $newUser->getId() !== 0 ) {
            $out->addHTML( '<div class="errorbox">' . $this->msg( 'authwp-rename-taken', $newName )->escaped() . '</div>' );
            $this->showRequests();
            return;
        }

        // Store the WP username mapping BEFORE the rename
        // This ensures AuthWP can still authenticate this user after the rename.
        // The WP username is whatever they had as their MW name (which matched WP) before any previous renames,
        // or an existing mapping if they were renamed before.
        $existingWpName = MediaWikiServices::getInstance()
            ->getUserOptionsManager()
            ->getOption( $oldUser, 'authwp-wp-username' );

        // Normalize to lowercase — WP user_login is always lowercase and
        // resolveRenamedUser() queries with strtolower() for consistency.
        $wpUsername = strtolower( $existingWpName ?: $oldName );

        // Perform the rename
        $rename = new RenameuserSQL(
            $oldName,
            $newName,
            $oldUser->getId(),
            $this->getUser(),
            [ 'reason' => $this->msg( 'authwp-rename-log-reason', $adminComment )->inContentLanguage()->text() ]
        );

        if ( !$rename->rename() ) {
            $out->addHTML( '<div class="errorbox">' . $this->msg( 'authwp-rename-failed' )->escaped() . '</div>' );
            $this->showRequests();
            return;
        }

        // Store the WP username mapping on the renamed user
        $renamedUser = $userFactory->newFromName( $newName );
        if ( $renamedUser && $renamedUser->getId() !== 0 ) {
            MediaWikiServices::getInstance()
                ->getUserOptionsManager()
                ->setOption( $renamedUser, 'authwp-wp-username', $wpUsername );
            $renamedUser->saveSettings();
        }

        // Update the request record
        $dbw->update(
            'authwp_rename_requests',
            [
                'aur_status' => 'approved',
                'aur_admin_id' => $this->getUser()->getId(),
                'aur_admin_comment' => $adminComment,
                'aur_resolved' => $dbw->timestamp( wfTimestampNow() ),
            ],
            [ 'aur_id' => $requestId ],
            __METHOD__
        );

        $out->addHTML( '<div class="successbox">'
            . $this->msg( 'authwp-rename-approved-success', $oldName, $newName )->escaped()
            . '</div>' );

        wfDebugLog( 'AuthWP', "Username rename approved: $oldName -> $newName (WP mapping: $wpUsername)" );

        $this->showRequests();
    }

    private function denyRequest( $requestId, $adminComment ) {
        $out = $this->getOutput();
        $dbw = MediaWikiServices::getInstance()->getDBLoadBalancer()->getConnection( DB_PRIMARY );

        $row = $dbw->selectRow( 'authwp_rename_requests', '*',
            [ 'aur_id' => $requestId, 'aur_status' => 'pending' ], __METHOD__ );

        if ( !$row ) {
            $out->addHTML( '<div class="errorbox">' . $this->msg( 'authwp-rename-not-found' )->escaped() . '</div>' );
            $this->showRequests();
            return;
        }

        $dbw->update(
            'authwp_rename_requests',
            [
                'aur_status' => 'denied',
                'aur_admin_id' => $this->getUser()->getId(),
                'aur_admin_comment' => $adminComment,
                'aur_resolved' => $dbw->timestamp( wfTimestampNow() ),
            ],
            [ 'aur_id' => $requestId ],
            __METHOD__
        );

        $out->addHTML( '<div class="warningbox">'
            . $this->msg( 'authwp-rename-denied-success', $row->aur_old_name, $row->aur_new_name )->escaped()
            . '</div>' );

        $this->showRequests();
    }

    protected function getGroupName() {
        return 'users';
    }
}
