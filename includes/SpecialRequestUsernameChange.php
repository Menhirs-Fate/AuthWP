<?php
/**
 * Special:RequestUsernameChange — allows logged-in users to request
 * a wiki username change.  The request must be approved by a sysop
 * via Special:ManageUsernameRequests before the rename takes effect.
 */

use MediaWiki\MediaWikiServices;

class SpecialRequestUsernameChange extends SpecialPage {

    public function __construct() {
        parent::__construct( 'RequestUsernameChange' );
    }

    public function doesWrites() {
        return true;
    }

    public function execute( $par ) {
        $this->requireLogin( 'authwp-rename-mustlogin' );
        $this->checkReadOnly();

        $out = $this->getOutput();
        $out->setPageTitle( $this->msg( 'authwp-rename-request-title' )->text() );

        $user = $this->getUser();
        $request = $this->getRequest();
        $dbr = MediaWikiServices::getInstance()->getDBLoadBalancer()->getConnection( DB_REPLICA );

        // Check for an existing pending request
        $pending = $dbr->selectRow(
            'authwp_rename_requests',
            [ 'aur_new_name', 'aur_timestamp' ],
            [ 'aur_user_id' => $user->getId(), 'aur_status' => 'pending' ],
            __METHOD__
        );

        if ( $pending ) {
            $out->addWikiMsg(
                'authwp-rename-already-pending',
                $pending->aur_new_name,
                $this->getLanguage()->timeanddate( $pending->aur_timestamp, true )
            );
            return;
        }

        // Handle form submission
        if ( $request->wasPosted() && $user->matchEditToken( $request->getVal( 'wpEditToken' ) ) ) {
            $this->handleSubmit();
            return;
        }

        // Show the form
        $this->showForm();
    }

    private function showForm( $error = '' ) {
        $out = $this->getOutput();
        $user = $this->getUser();

        if ( $error ) {
            $out->addHTML( '<div class="errorbox">' . htmlspecialchars( $error ) . '</div>' );
        }

        $out->addWikiMsg( 'authwp-rename-request-intro', $user->getName() );

        $formDescriptor = [
            'newname' => [
                'type' => 'text',
                'label-message' => 'authwp-rename-newname',
                'required' => true,
                'maxlength' => 255,
                'validation-callback' => [ $this, 'validateNewName' ],
            ],
            'reason' => [
                'type' => 'text',
                'label-message' => 'authwp-rename-reason',
                'required' => false,
                'maxlength' => 500,
            ],
        ];

        $htmlForm = HTMLForm::factory( 'ooui', $formDescriptor, $this->getContext() );
        $htmlForm
            ->setSubmitTextMsg( 'authwp-rename-submit' )
            ->setSubmitCallback( [ $this, 'onFormSubmit' ] )
            ->show();
    }

    /**
     * Validate the requested new username.
     */
    public function validateNewName( $newName, $allData ) {
        $newName = trim( $newName );
        if ( $newName === '' ) {
            return $this->msg( 'authwp-rename-empty' )->text();
        }

        // Must be a valid MediaWiki username
        $canonName = MediaWikiServices::getInstance()
            ->getUserNameUtils()
            ->getCanonical( $newName, 'creatable' );

        if ( $canonName === false ) {
            return $this->msg( 'authwp-rename-invalid' )->text();
        }

        // Must not already exist
        $existingUser = MediaWikiServices::getInstance()
            ->getUserFactory()
            ->newFromName( $canonName );
        if ( $existingUser && $existingUser->getId() !== 0 ) {
            return $this->msg( 'authwp-rename-taken', $canonName )->text();
        }

        // Must be different from current name
        if ( $canonName === $this->getUser()->getName() ) {
            return $this->msg( 'authwp-rename-same' )->text();
        }

        return true;
    }

    /**
     * HTMLForm submit callback.
     */
    public function onFormSubmit( $formData ) {
        $user = $this->getUser();
        $newName = trim( $formData['newname'] );
        $reason = trim( $formData['reason'] ?? '' );

        $canonName = MediaWikiServices::getInstance()
            ->getUserNameUtils()
            ->getCanonical( $newName, 'creatable' );

        $dbw = MediaWikiServices::getInstance()->getDBLoadBalancer()->getConnection( DB_PRIMARY );

        $dbw->insert(
            'authwp_rename_requests',
            [
                'aur_user_id'  => $user->getId(),
                'aur_old_name' => $user->getName(),
                'aur_new_name' => $canonName,
                'aur_reason'   => $reason,
                'aur_status'   => 'pending',
                'aur_timestamp' => $dbw->timestamp( wfTimestampNow() ),
            ],
            __METHOD__
        );

        $out = $this->getOutput();
        $out->addWikiMsg( 'authwp-rename-request-success', $canonName );

        return true;
    }

    private function handleSubmit() {
        // Handled by HTMLForm callback
    }

    protected function getGroupName() {
        return 'users';
    }
}
