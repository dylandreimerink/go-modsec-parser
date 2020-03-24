# ModSecurity config parser for Go

This is a parser for [ModSecurity](https://github.com/SpiderLabs/ModSecurity) configuration files

NOTE/WARNING: this library is still in it's early days and is not yet fully functional

## TODO

- [ ] Full support for CRS(Core Rule Set) ([See progress](docs/crs-checklist.md))
- [ ] Full support for ModSecurity V2 config ([See progress](docs/modsecv2-checklist.md))
- [ ] Full support for ModSecurity V3 config
- [ ] Fully unit tested parsing
- [ ] AST walker / traversal
- [ ] .data file parsing
- [ ] Full support for ModSecurity V3 config

## Wishlist

- [ ] AST to string
- [ ] ModSecurity validation / linting (Regex, XPath, ect...) (Only one disruptive action per rule, no using variables in the correct phase)
- [ ] Rule optimization
- [ ] Rule dependency resolver
