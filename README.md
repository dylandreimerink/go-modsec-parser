# ModSecurity config parser for Go

This is a parser for [ModSecurity](https://github.com/SpiderLabs/ModSecurity) configuration files

NOTE/WARNING: this library is still in it's early days and is not yet fully functional

## TODO

- [ ] Fully unit tested parsing
- [ ] Fully tested CRS
- [ ] Full support ModSecurity V2/3 config support
- [ ] AST walker / traversal
- [ ] .data file parsing
- [ ] Node classification (variables: phase 1, phase 2, ect..; actions: flow, metadata, disruptive, ect...)

## Wishlist

- [ ] AST to string
- [ ] ModSecurity validation / linting (Regex, XPath, ect...) (Only one disruptive action per rule, no using variables in the correct phase)
- [ ] Rule optimization
- [ ] Rule dependency resolver