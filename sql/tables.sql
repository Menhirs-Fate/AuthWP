-- AuthWP username change requests table
CREATE TABLE IF NOT EXISTS /*_*/authwp_rename_requests (
    aur_id        INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
    aur_user_id   INT UNSIGNED NOT NULL,
    aur_old_name  VARCHAR(255) NOT NULL,
    aur_new_name  VARCHAR(255) NOT NULL,
    aur_reason    BLOB DEFAULT NULL,
    aur_status    ENUM('pending','approved','denied') NOT NULL DEFAULT 'pending',
    aur_admin_id  INT UNSIGNED DEFAULT NULL,
    aur_admin_comment BLOB DEFAULT NULL,
    aur_timestamp BINARY(14) NOT NULL,
    aur_resolved  BINARY(14) DEFAULT NULL
) /*$wgDBTableOptions*/;

CREATE INDEX /*i*/aur_status_ts ON /*_*/authwp_rename_requests (aur_status, aur_timestamp);
CREATE INDEX /*i*/aur_user ON /*_*/authwp_rename_requests (aur_user_id);
