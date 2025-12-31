package api

import (
	"net/http"
)

// ProfilesResponse contains the list of available mount profiles.
type ProfilesResponse struct {
	Profiles []ProfileInfo `json:"profiles"`
}

// ProfileInfo describes a mount profile.
type ProfileInfo struct {
	Name       string      `json:"name"`
	BasePolicy string      `json:"base_policy"`
	Mounts     []MountInfo `json:"mounts"`
}

// MountInfo describes a single mount point within a profile.
type MountInfo struct {
	Path   string `json:"path"`
	Policy string `json:"policy"`
}

// handleListProfiles returns the list of configured mount profiles.
func (a *App) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := make([]ProfileInfo, 0)

	if a.cfg != nil && a.cfg.MountProfiles != nil {
		for name, p := range a.cfg.MountProfiles {
			mounts := make([]MountInfo, 0, len(p.Mounts))
			for _, m := range p.Mounts {
				mounts = append(mounts, MountInfo{
					Path:   m.Path,
					Policy: m.Policy,
				})
			}
			profiles = append(profiles, ProfileInfo{
				Name:       name,
				BasePolicy: p.BasePolicy,
				Mounts:     mounts,
			})
		}
	}

	writeJSON(w, http.StatusOK, ProfilesResponse{Profiles: profiles})
}
