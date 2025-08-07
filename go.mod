module github.com/agilira/go-crypto

go 1.23.11

require (
	github.com/agilira/go-errors v1.0.0
	golang.org/x/crypto v0.40.0
)

require golang.org/x/sys v0.34.0 // indirect

replace github.com/agilira/go-errors => ../go-errors
