module registry-token-server

go 1.21

require (
	github.com/Sirupsen/logrus v1.0.6
	github.com/docker/distribution v2.8.2+incompatible
	github.com/docker/libtrust v0.0.0-20160708172513-aabc10ec26b7
	github.com/gophercloud/gophercloud v1.14.1
	github.com/gorilla/mux v1.8.1
)

require (
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/sys v0.13.0 // indirect
)

replace github.com/Sirupsen/logrus => github.com/sirupsen/logrus v1.9.3
