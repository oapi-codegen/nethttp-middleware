package gorilla

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	middleware "github.com/oapi-codegen/nethttp-middleware"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

//go:embed test_spec.yaml
var testSchema []byte

func doGet(t *testing.T, mux http.Handler, rawURL string) *httptest.ResponseRecorder {
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Invalid url: %s", rawURL)
	}

	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	require.NoError(t, err)

	req.Header.Set("accept", "application/json")

	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	return rr
}

func doPost(t *testing.T, mux http.Handler, rawURL string, jsonBody interface{}) *httptest.ResponseRecorder {
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Invalid url: %s", rawURL)
	}

	data, err := json.Marshal(jsonBody)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, u.String(), bytes.NewReader(data))
	require.NoError(t, err)

	req.Header.Set("content-type", "application/json")

	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	return rr
}

func TestOapiRequestValidator(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	r := mux.NewRouter()

	// register middleware
	r.Use(middleware.OapiRequestValidator(spec))

	// basic cases
	testRequestValidatorBasicFunctions(t, r)
}

func TestOapiRequestValidatorWithOptionsMultiError(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	r := mux.NewRouter()

	// Set up an authenticator to check authenticated function. It will allow
	// access to "someScope", but disallow others.
	options := middleware.Options{
		Options: openapi3filter.Options{
			ExcludeRequestBody:    false,
			ExcludeResponseBody:   false,
			IncludeResponseStatus: true,
			MultiError:            true,
		},
	}

	// register middleware
	r.Use(middleware.OapiRequestValidatorWithOptions(spec, &options))

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	r.HandleFunc("/multiparamresource", func(w http.ResponseWriter, r *http.Request) {
		called = true
	}).Methods("GET")

	// Let's send a good request, it should pass
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=50&id2=50")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Let's send a request with a missing parameter, it should return
	// a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=50")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 2 missing parameters, it should return
	// a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id\"")
			assert.Contains(t, string(body), "value is required but missing")
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 1 missing parameter, and another outside
	// or the parameters. It should return a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=500")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id\"")
			assert.Contains(t, string(body), "number must be at most 100")
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a parameters that do not meet spec. It should
	// return a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=abc&id2=1")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id\"")
			assert.Contains(t, string(body), "value abc: an invalid integer: invalid syntax")
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "number must be at least 10")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}
}

func TestOapiRequestValidatorWithOptionsMultiErrorAndCustomHandler(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	r := mux.NewRouter()

	// Set up an authenticator to check authenticated function. It will allow
	// access to "someScope", but disallow others.
	options := middleware.Options{
		Options: openapi3filter.Options{
			ExcludeRequestBody:    false,
			ExcludeResponseBody:   false,
			IncludeResponseStatus: true,
			MultiError:            true,
		},
		MultiErrorHandler: func(me openapi3.MultiError) (int, error) {
			return http.StatusTeapot, me
		},
	}

	// register middleware
	r.Use(middleware.OapiRequestValidatorWithOptions(spec, &options))

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	r.HandleFunc("/multiparamresource", func(w http.ResponseWriter, r *http.Request) {
		called = true
	}).Methods("GET")

	// Let's send a good request, it should pass
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=50&id2=50")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Let's send a request with a missing parameter, it should return
	// a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=50")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 2 missing parameters, it should return
	// a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id\"")
			assert.Contains(t, string(body), "value is required but missing")
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a 1 missing parameter, and another outside
	// or the parameters. It should return a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=500")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id\"")
			assert.Contains(t, string(body), "number must be at most 100")
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "value is required but missing")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Let's send a request with a parameters that do not meet spec. It should
	// return a bad status
	{
		rec := doGet(t, r, "http://deepmap.ai/multiparamresource?id=abc&id2=1")
		assert.Equal(t, http.StatusTeapot, rec.Code)
		body, err := io.ReadAll(rec.Body)
		if assert.NoError(t, err) {
			assert.Contains(t, string(body), "parameter \"id\"")
			assert.Contains(t, string(body), "value abc: an invalid integer: invalid syntax")
			assert.Contains(t, string(body), "parameter \"id2\"")
			assert.Contains(t, string(body), "number must be at least 10")
		}
		assert.False(t, called, "Handler should not have been called")
		called = false
	}
}

func TestOapiRequestValidatorWithOptions(t *testing.T) {
	spec, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing OpenAPI spec")

	r := mux.NewRouter()

	// Set up an authenticator to check authenticated function. It will allow
	// access to "someScope", but disallow others.
	options := middleware.Options{
		ErrorHandler: func(w http.ResponseWriter, message string, statusCode int) {
			http.Error(w, "test: "+message, statusCode)
		},
		Options: openapi3filter.Options{
			AuthenticationFunc: func(c context.Context, input *openapi3filter.AuthenticationInput) error {

				for _, s := range input.Scopes {
					if s == "someScope" {
						return nil
					}
				}
				return errors.New("unauthorized")
			},
		},
	}

	// register middleware
	r.Use(middleware.OapiRequestValidatorWithOptions(spec, &options))

	// basic cases
	testRequestValidatorBasicFunctions(t, r)

	called := false

	r.HandleFunc("/protected_resource", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}).Methods("GET")

	// Call a protected function to which we have access
	{
		rec := doGet(t, r, "http://deepmap.ai/protected_resource")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	r.HandleFunc("/protected_resource2", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}).Methods("GET")
	// Call a protected function to which we dont have access
	{
		rec := doGet(t, r, "http://deepmap.ai/protected_resource2")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	r.HandleFunc("/protected_resource_401", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}).Methods("GET")
	// Call a protected function without credentials
	{
		rec := doGet(t, r, "http://deepmap.ai/protected_resource_401")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "test: security requirements failed: unauthorized\n", rec.Body.String())
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

}

func testRequestValidatorBasicFunctions(t *testing.T, r *mux.Router) {

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	r.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		called = true
	}).Methods("GET")

	// Let's send the request to the wrong server, this should return 404
	{
		rec := doGet(t, r, "http://not.deepmap.ai/resource")
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}

	// Let's send a good request, it should pass
	{
		rec := doGet(t, r, "http://deepmap.ai/resource")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Send an out-of-spec parameter
	{
		rec := doGet(t, r, "http://deepmap.ai/resource?id=500")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Send a bad parameter type
	{
		rec := doGet(t, r, "http://deepmap.ai/resource?id=foo")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Send a request with wrong HTTP method
	{
		body := struct {
			Name string `json:"name"`
		}{
			Name: "Marcin",
		}
		rec := doPost(t, r, "http://deepmap.ai/resource", body)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Add a handler for the POST message
	r.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}).Methods("POST")

	called = false
	// Send a good request body
	{
		body := struct {
			Name string `json:"name"`
		}{
			Name: "Marcin",
		}
		rec := doPost(t, r, "http://deepmap.ai/resource", body)
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Send a malformed body
	{
		body := struct {
			Name int `json:"name"`
		}{
			Name: 7,
		}
		rec := doPost(t, r, "http://deepmap.ai/resource", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

}
