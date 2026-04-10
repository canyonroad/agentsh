package session

import (
	"fmt"
	"sort"
	"strings"
)

// CheckEnvCollisions returns an error if any service env var name
// collides with an env_inject key. Both maps use env var names as keys.
func CheckEnvCollisions(serviceEnv, envInject map[string]string) error {
	if len(serviceEnv) == 0 || len(envInject) == 0 {
		return nil
	}
	// Build normalized key set from envInject.
	injectKeys := make(map[string]bool, len(envInject))
	for k := range envInject {
		injectKeys[envVarKey(k)] = true
	}
	var collisions []string
	for name := range serviceEnv {
		if injectKeys[envVarKey(name)] {
			collisions = append(collisions, name)
		}
	}
	if len(collisions) == 0 {
		return nil
	}
	sort.Strings(collisions)
	return fmt.Errorf("env_inject_service_collision: %s", strings.Join(collisions, ", "))
}
