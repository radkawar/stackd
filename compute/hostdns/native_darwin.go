package hostdns

func nativeBackend() (backend, error) {
	return fileBackend{directory: "/etc/resolver"}, nil
}
