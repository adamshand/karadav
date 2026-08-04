# KaraDAV - A lightweight WebDAV server, compatible with ownCloud and NextCloud clients

<img align="right" style="float: right" src="www/logo.svg" />

This is a fork of [KaraDAV](https://github.com/kd2org/karadav/), a lightweight PHP WebDAV server that supports syncing via the NextCloud and OwnCloud clients. 

This fork was created because I wanted something simple, light and fast to sync files between my Mac, Linux & iOS computers. KaraDAV was the best option I could find, but the author wasn't interested in adding support for iOS and macOS. 

The initial fork added support for the NextCloud and OwnCloud clients on macOS and iOS (some of my changes have been merged upstream). Since then I've added a few more features:

 - Added macOS Finder virtual-file and sharing integration.
 - Added internal user shares and password-protected public links.
 - Added custom user avatars.
 - Improved media browsing, favourites, previews, file metadata, quotas, and ETags.
 - Improved desktop/mobile login flows and app-password handling.
 - Fixed chunked uploads, synchronisation, COPY/MOVE operations, and cache updates.
 - Added stronger path validation, share permissions, session expiry, password throttling, and symlink protection.
 - Added automatic database migrations and security regression tests.

I've been using this daily since May 2026 and "it works great for me". If you find a bug or security issue please let me know, but no support is offered. If you would like to use it, fork it and have fun. 💋
