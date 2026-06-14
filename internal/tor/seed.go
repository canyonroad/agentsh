package tor

// DirectoryAuthoritySeed returns the well-known Tor directory-authority
// IPv4 addresses. These are near-static (changes require a Tor release)
// and a client must contact one — or a fallback dir — to bootstrap, so
// this list breaks Tor without any external feed. Source: Tor's
// src/app/config/auth_dirs.inc. Operators extend coverage via the
// onionoo relay feed or relay_feed.local_lists.
func DirectoryAuthoritySeed() []string {
	return []string{
		"128.31.0.39",    // moria1
		"86.59.21.38",    // tor26
		"199.58.81.140",  // dizum
		"192.36.123.159", // bastet
		"66.111.2.131",   // Faravahar
		"131.188.40.189", // gabelmoo
		"193.23.244.244", // dannenberg
		"171.25.193.9",   // maatuska
		"154.35.175.225", // longclaw
		"204.13.164.118", // serge
	}
}
