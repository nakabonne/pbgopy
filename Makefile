
.PHONY: test
test:
	go test -race -v -coverpkg=./... -covermode=atomic -coverprofile=coverage.txt ./...
