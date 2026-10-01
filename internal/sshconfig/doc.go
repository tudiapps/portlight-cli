// Package sshconfig parses ~/.ssh/config into the host records the app
// consumes: alias, HostName, User, Port, IdentityFile and ProxyJump. It also
// resolves Include directives and converts PuTTY .ppk keys on Windows.
package sshconfig
