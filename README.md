# KaraDAV - A lightweight WebDAV server, compatible with ownCloud and NextCloud clients

<img align="right" style="float: right" src="www/logo.svg" />

[**Donate to this project**](https://kd2.org/donate)

This is a fork of [KaraDAV](https://github.com/kd2org/karadav/), a lightweight PHP WebDAV server that supports syncing via the NextCloud and OwnCloud clients. 

This fork was created to support the iOS and macOS clients (which the original didn't support, though some of my changes have been merged upstream).  Since then I've added a few more features which I wanted.

 - Added macOS Finder virtual-file and sharing integration.
 - Added internal user shares and password-protected public links.
 - Added custom user avatars.
 - Improved media browsing, favourites, previews, file metadata, quotas, and ETags.
 - Improved desktop/mobile login flows and app-password handling.
 - Fixed chunked uploads, synchronisation, COPY/MOVE operations, and cache updates.
 - Added stronger path validation, share permissions, session expiry, password throttling, and symlink protection.
 - Added automatic database migrations and security regression tests.

I've been using this daily since May 2026 and "it works great for me". If you find a bug or security issue please let me know, but no support is offered. If you would like to use it, fork it and have fun. 💋
