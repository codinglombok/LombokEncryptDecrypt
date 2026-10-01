module github.com/codinglombok/lombokencryptdecrypt-go

go 1.22

require (
	golang.org/x/crypto v0.24.0
	golang.org/x/sys v0.21.0
)

// No external crypto dependencies — pure Go implementation
// golang.org/x/crypto used only for tested reference comparison in tests
