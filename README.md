<!-- -*- mode: gfm -*- -->

AuthWP is a [MediaWiki](https://www.mediawiki.org) extension that
allows authentication with [WordPress](https://wordpress.org)
credentials. It is a rewrite
of [WPMW](https://www.mediawiki.org/w/index.php?oldid=3746476)
by [Ciaran Gultnieks](https://github.com/CiaranG) and is intended to
provide essentially the same functionality using `SessionManager` and
`AuthenticationProvider` introduced in MediaWiki 1.27. In particular:

This repository is a fork of AuthWP focused on staff-only wiki access.
It keeps WordPress-backed authentication but restricts who can sign in
to MediaWiki.

- A valid WordPress session allows access to MediaWiki.
  Authenticating to MediaWiki with WordPress credentials signs the
  user in to WordPress.
- Logging out from MediaWiki also logs the user out from WordPress and
  <i>vice versa</i>.
- User passwords are maintained in WordPress only, but can be changed
  from either MediaWiki or WordPress. MediaWiki users
  <em>without</em> corresponding WordPress accounts will have their
  passwords maintained by MediaWiki.
- MediaWiki can be configured to auto-create accounts for existing
  WordPress users when they first access the wiki. Generally, user
  management will have to be done from WordPress, but because
  MediaWiki requires a different set of attributes for its users
  (<i>e.g.</i> group membership and number of edits), it is not
  possible to do away with the MediaWiki accounts entirely.
- In this fork, MediaWiki registration is disabled. Users must already
  have WordPress accounts.

See the
MediaWiki
[Extension page](https://www.mediawiki.org/wiki/Extension:AuthWP) for
further documentation.

## Fork-specific authentication behavior

This fork adds two policy controls:

- Registration restriction: MediaWiki-side account registration is
  disabled.
- Role-filtered login: MediaWiki sign-in is allowed only when the
  authenticated WordPress user has at least one configured allowed
  role.

If an existing WordPress user signs in successfully and passes role
checks, MediaWiki can still auto-create the corresponding local wiki
account on first login.

## Restricting login to staff roles

This extension can be configured to allow MediaWiki sign-in only for
specific WordPress roles. Users without one of the allowed roles are
denied sign-in with a "staff only" message.

In your LocalSettings.php:

```php
$wgAuthWPAllowedRoles = [ 'administrator', 'editor' ];
```

If `AuthWPAllowedRoles` is empty (the default), role-based access
restriction is disabled.
