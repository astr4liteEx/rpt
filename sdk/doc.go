// Package sdk is the public API rpt plugins build on: the record wire types,
// the Records stream reader, and the plugin entry point. Changes follow the
// schema versioning rule: adding a field keeps the version; renaming or
// removing one bumps it after a deprecation release.
package sdk
