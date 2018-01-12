# Change Log

## [Unreleased]

## [v0.4.1] - 2018-01-11

### Changed

* Stopped enabling default features for `hyper`.

## [v0.4.0] - 2018-01-11

### Removed

* The `HttpsConnector::danger_disable_hostname_verification` method has been removed. Instead, use
    a callback which configures the `ConnectConfiguration` directly.

### Changed

* Upgraded to openssl 0.10.
* The `HttpsConnector::ssl_callback` method has been renamed to `HttpsConnector::set_callback`,
    and is passed a reference to the `ConnectConfiguration` rather than just the `SslRef`.

## Older

Look at the [release tags] for information about older releases.

[Unreleased]: https://github.com/sfackler/hyper-openssl/compare/0.4.1...master
[v0.4.1]: https://github.com/sfackler/hyper-openssl/compare/0.4.0...0.4.1
[v0.4.0]: https://github.com/sfackler/hyper-openssl/compare/0.3.1...0.4.0
[release tags]: https://github.com/sfackler/hyper-openssl/releases
