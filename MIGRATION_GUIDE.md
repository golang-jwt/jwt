## Migration Guide (v3.2.1)

Starting from (v3.2.1)[https://github.com/golang-jwt/jwt/releases/tag/v3.2.1], the import path has changed from `github.com/dgrijalva/jwt-go` to `github.com/golang-jwt/jwt`. Future releases will be using the `github.com/golang-jwt/jwt` import path and continue the existing versioning scheme of `v3.x.x+incompatible`. Backwards-compatbile patches and fixes will be done on the `v3` release branch, where as new build-breaking features will be developed in a `v4` release, possibly including a SIV-style import path.

TODO: explain how to replace

## Older releases (before v3.2.0)

The original migration guide for older releases can be found at https://github.com/dgrijalva/jwt-go/blob/master/MIGRATION_GUIDE.md.