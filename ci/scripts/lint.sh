#!/bin/bash -eux

pushd dis-authentication-stub
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.62.2
  make lint
popd
