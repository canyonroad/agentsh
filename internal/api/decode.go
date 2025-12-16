package api

import (
	"encoding/json"
	"errors"
	"net/http"
)

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, invalidMsg string) bool {
	if invalidMsg == "" {
		invalidMsg = "invalid json"
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "request body too large"})
			return false
		}
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": invalidMsg})
		return false
	}
	return true
}
