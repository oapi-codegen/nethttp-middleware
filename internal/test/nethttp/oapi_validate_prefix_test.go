package gorilla

import (
	"context"
	_ "embed"
	"net/http"
	"testing"

	middleware "github.com/oapi-codegen/nethttp-middleware"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// prefixTestSpec defines a minimal spec with /resource (GET+POST) for prefix testing
const prefixTestSpec = `
openapi: "3.0.0"
info:
  version: 1.0.0
  title: TestServer
paths:
  /resource:
    get:
      operationId: getResource
      parameters:
        - name: id
          in: query
          schema:
            type: integer
            minimum: 10
            maximum: 100
      responses:
        '200':
          description: success
    post:
      operationId: createResource
      responses:
        '204':
          description: No content
      requestBody:
        required: true
        content:
          application/json:
            schema:
              properties:
                name:
                  type: string
              additionalProperties: false
`

func loadPrefixSpec(t *testing.T) *openapi3.T {
	t.Helper()
	spec, err := openapi3.NewLoader().LoadFromData([]byte(prefixTestSpec))
	require.NoError(t, err)
	spec.Servers = nil
	return spec
}

// setupPrefixHandler creates a mux with a handler at the given handlerPath
// that records whether it was called and what path it saw.
func setupPrefixHandler(t *testing.T, handlerPath string) (*http.ServeMux, *bool, *string) {
	t.Helper()
	called := new(bool)
	observedPath := new(string)

	mux := http.NewServeMux()
	mux.HandleFunc(handlerPath, func(w http.ResponseWriter, r *http.Request) {
		*called = true
		*observedPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	})
	return mux, called, observedPath
}

func TestPrefix_ErrorHandler_ValidRequest(t *testing.T) {
	spec := loadPrefixSpec(t)
	mux, called, observedPath := setupPrefixHandler(t, "/api/v1/resource")

	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/api/v1",
	})
	server := mw(mux)

	body := struct {
		Name string `json:"name"`
	}{Name: "test"}

	rec := doPost(t, server, "http://example.com/api/v1/resource", body)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, *called, "handler should have been called")
	assert.Equal(t, "/api/v1/resource", *observedPath, "handler should see the original path, not the stripped one")
}

func TestPrefix_ErrorHandler_InvalidRequest(t *testing.T) {
	spec := loadPrefixSpec(t)
	mux, called, _ := setupPrefixHandler(t, "/api/v1/resource")

	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/api/v1",
	})
	server := mw(mux)

	// Send a request with out-of-spec query param (id=500, max is 100)
	rec := doGet(t, server, "http://example.com/api/v1/resource?id=500")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, *called, "handler should not have been called for invalid request")
}

func TestPrefix_ErrorHandlerWithOpts_ValidRequest(t *testing.T) {
	spec := loadPrefixSpec(t)
	mux, called, observedPath := setupPrefixHandler(t, "/api/v1/resource")

	var errHandlerCalled bool
	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/api/v1",
		ErrorHandlerWithOpts: func(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts middleware.ErrorHandlerOpts) {
			errHandlerCalled = true
			http.Error(w, err.Error(), opts.StatusCode)
		},
	})
	server := mw(mux)

	body := struct {
		Name string `json:"name"`
	}{Name: "test"}

	rec := doPost(t, server, "http://example.com/api/v1/resource", body)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, *called, "handler should have been called")
	assert.False(t, errHandlerCalled, "error handler should not have been called")
	assert.Equal(t, "/api/v1/resource", *observedPath, "handler should see the original path, not the stripped one")
}

func TestPrefix_ErrorHandlerWithOpts_InvalidRequest(t *testing.T) {
	spec := loadPrefixSpec(t)
	mux, called, _ := setupPrefixHandler(t, "/api/v1/resource")

	var errHandlerCalled bool
	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/api/v1",
		ErrorHandlerWithOpts: func(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts middleware.ErrorHandlerOpts) {
			errHandlerCalled = true
			http.Error(w, err.Error(), opts.StatusCode)
		},
	})
	server := mw(mux)

	rec := doGet(t, server, "http://example.com/api/v1/resource?id=500")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.False(t, *called, "handler should not have been called")
	assert.True(t, errHandlerCalled, "error handler should have been called")
}

func TestPrefix_RequestWithoutPrefix_NotMatched(t *testing.T) {
	spec := loadPrefixSpec(t)
	mux, called, _ := setupPrefixHandler(t, "/resource")

	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/api/v1",
	})
	server := mw(mux)

	// A request to /resource (without the prefix) should not match the
	// prefix and should be treated as if no prefix stripping happened.
	// Since /resource IS in the spec, this should still validate.
	rec := doGet(t, server, "http://example.com/resource")
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, *called, "handler should have been called for path that doesn't have the prefix")
}

func TestPrefix_PartialSegmentMatch_NotStripped(t *testing.T) {
	spec := loadPrefixSpec(t)

	// Register handler at the path that would result from incorrect partial stripping
	mux := http.NewServeMux()

	var resourceV2Called bool
	mux.HandleFunc("/api-v2/resource", func(w http.ResponseWriter, r *http.Request) {
		resourceV2Called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/api",
	})
	server := mw(mux)

	// /api-v2/resource should NOT have "/api" stripped to become "-v2/resource"
	// The prefix must match on a path segment boundary.
	rec := doGet(t, server, "http://example.com/api-v2/resource")
	// The prefix doesn't match on a segment boundary, so no stripping happens.
	// /api-v2/resource is not in the spec → 404.
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.False(t, resourceV2Called, "handler should not have been called")
}

func TestPrefix_ExactPrefixOnly_NoTrailingSlash(t *testing.T) {
	spec := loadPrefixSpec(t)
	mux, called, _ := setupPrefixHandler(t, "/api/resource")

	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/api",
	})
	server := mw(mux)

	// /api/resource → strip /api → /resource (which is in the spec)
	body := struct {
		Name string `json:"name"`
	}{Name: "test"}

	rec := doPost(t, server, "http://example.com/api/resource", body)
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.True(t, *called, "handler should have been called")
}

func TestPrefix_ErrorHandlerWithOpts_HandlerSeesOriginalPath(t *testing.T) {
	spec := loadPrefixSpec(t)
	mux, _, observedPath := setupPrefixHandler(t, "/prefix/resource")

	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Prefix: "/prefix",
		ErrorHandlerWithOpts: func(ctx context.Context, err error, w http.ResponseWriter, r *http.Request, opts middleware.ErrorHandlerOpts) {
			http.Error(w, err.Error(), opts.StatusCode)
		},
	})
	server := mw(mux)

	rec := doGet(t, server, "http://example.com/prefix/resource")
	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "/prefix/resource", *observedPath, "downstream handler must see the original un-stripped path")
}

func TestPrefix_WithAuthenticationFunc(t *testing.T) {
	spec := loadPrefixSpec(t)

	// Add a protected endpoint to the spec for this test
	protectedSpec := `
openapi: "3.0.0"
info:
  version: 1.0.0
  title: TestServer
paths:
  /resource:
    get:
      operationId: getResource
      security:
        - BearerAuth:
            - someScope
      responses:
        '200':
          description: success
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
`
	_ = spec // unused, use protectedSpec instead
	pSpec, err := openapi3.NewLoader().LoadFromData([]byte(protectedSpec))
	require.NoError(t, err)
	pSpec.Servers = nil

	mux := http.NewServeMux()
	var called bool
	mux.HandleFunc("/api/resource", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	mw := middleware.OapiRequestValidatorWithOptions(pSpec, &middleware.Options{
		Prefix: "/api",
		Options: openapi3filter.Options{
			AuthenticationFunc: func(ctx context.Context, input *openapi3filter.AuthenticationInput) error {
				return nil // always allow
			},
		},
	})
	server := mw(mux)

	rec := doGet(t, server, "http://example.com/api/resource")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, called, "handler should have been called when auth passes")
}
