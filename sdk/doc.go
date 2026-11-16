// Package sdk is the Go implementation of the rpt plugin protocol
// (docs/plugin-protocol.md): the record wire types, the Records stream
// reader, SetMember, and the plugin entry points Run, Main and Bin. Plugins
// in other languages follow the protocol directly; this package is a
// convenience, never a requirement.
//
// Versioning: the module is tagged v0.N.M; a breaking change to this
// package's API bumps N. The record format is versioned separately by
// schema_version: adding a field keeps it; renaming or removing one bumps it
// after a deprecation release.
package sdk
