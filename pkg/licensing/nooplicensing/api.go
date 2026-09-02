package nooplicensing

import (
	"net/http"

	"github.com/SigNoz/signoz/pkg/errors"
	"github.com/SigNoz/signoz/pkg/http/render"
	"github.com/SigNoz/signoz/pkg/licensing"
)

type noopLicensingAPI struct{}

func NewLicenseAPI() licensing.API {
	return &noopLicensingAPI{}
}

// communityLicenseResponse returns a complete license payload that satisfies the
// frontend LicenseResModel type.  The community edition has no real license, so
// every field is set to a safe zero / default value.
func communityLicenseResponse() map[string]any {
	return map[string]any{
		"key":    "",
		"status": "VALID",
		"state":  "ACTIVATED",
		"event_queue": map[string]any{
			"event":        "",
			"status":       "",
			"scheduled_at": "0",
			"created_at":   "0",
			"updated_at":   "0",
		},
		"platform":   "SELF_HOSTED",
		"created_at": "0",
		"updated_at": "0",
		"plan": map[string]any{
			"created_at":  "0",
			"description": "",
			"is_active":   true,
			"name":        "Community",
			"updated_at":  "0",
		},
		"plan_id":     "",
		"free_until":  "0",
		"valid_from":  0,
		"valid_until": 0,
	}
}

func (api *noopLicensingAPI) Activate(rw http.ResponseWriter, r *http.Request) {
	render.Success(rw, http.StatusOK, communityLicenseResponse())
}

func (api *noopLicensingAPI) GetActive(rw http.ResponseWriter, r *http.Request) {
	render.Success(rw, http.StatusOK, communityLicenseResponse())
}

func (api *noopLicensingAPI) Refresh(rw http.ResponseWriter, r *http.Request) {
	render.Error(rw, errors.New(errors.TypeUnsupported, licensing.ErrCodeUnsupported, "not implemented"))
}

func (api *noopLicensingAPI) Checkout(rw http.ResponseWriter, r *http.Request) {
	render.Error(rw, errors.New(errors.TypeUnsupported, licensing.ErrCodeUnsupported, "not implemented"))
}

func (api *noopLicensingAPI) Portal(rw http.ResponseWriter, r *http.Request) {
	render.Error(rw, errors.New(errors.TypeUnsupported, licensing.ErrCodeUnsupported, "not implemented"))
}
