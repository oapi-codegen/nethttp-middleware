package gorilla

import (
	"context"
	_ "embed"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/oapi-codegen/testutil"
	middleware "github.com/oapi-codegen/nethttp-middleware"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
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

	response := testutil.NewRequest().Get(u.RequestURI()).WithHost(u.Host).WithAcceptJson().GoWithHTTPHandler(t, mux)
	return response.Recorder
}

func doPost(t *testing.T, mux http.Handler, rawURL string, jsonBody interface{}) *httptest.ResponseRecorder {
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Invalid url: %s", rawURL)
	}

	response := testutil.NewRequest().Post(u.RequestURI()).WithHost(u.Host).WithJsonBody(jsonBody).GoWithHTTPHandler(t, mux)
	return response.Recorder
}

// use wraps a given http.ServeMux with middleware for execution
func use(r *http.ServeMux, mw func(next http.Handler) http.Handler) http.Handler {
	return mw(r)
}

func TestOapiRequestValidator(t *testing.T) {
	swagger, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing swagger")

	r := http.NewServeMux()

	// create middleware
	mw := middleware.OapiRequestValidator(swagger)

	// basic cases
	testRequestValidatorBasicFunctions(t, r, mw)
}

func TestOapiRequestValidatorWithOptionsMultiError(t *testing.T) {
	swagger, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing swagger")

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

	r := http.NewServeMux()

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	r.HandleFunc("/multiparamresource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		called = true
	})

	// register middleware
	mw := middleware.OapiRequestValidatorWithOptions(swagger, &options)
	server := mw(r)

	// Let's send a good request, it should pass
	{
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=50&id2=50")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Let's send a request with a missing parameter, it should return
	// a bad status
	{
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=50")
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
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource")
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
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=500")
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
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=abc&id2=1")
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
	swagger, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing swagger")

	r := http.NewServeMux()

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

	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	r.HandleFunc("/multiparamresource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		called = true
	})

	// register middleware
	server := use(r, middleware.OapiRequestValidatorWithOptions(swagger, &options))

	// Let's send a good request, it should pass
	{
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=50&id2=50")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Let's send a request with a missing parameter, it should return
	// a bad status
	{
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=50")
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
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource")
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
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=500")
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
		rec := doGet(t, server, "http://deepmap.ai/multiparamresource?id=abc&id2=1")
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
	swagger, err := openapi3.NewLoader().LoadFromData(testSchema)
	require.NoError(t, err, "Error initializing swagger")

	r := http.NewServeMux()

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
	mw := middleware.OapiRequestValidatorWithOptions(swagger, &options)
	server := use(r, mw)

	// basic cases
	testRequestValidatorBasicFunctions(t, r, mw)

	called := false

	r.HandleFunc("/protected_resource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	// Call a protected function to which we have access
	{
		rec := doGet(t, server, "http://deepmap.ai/protected_resource")
		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	r.HandleFunc("/protected_resource2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	// Call a protected function to which we dont have access
	{
		rec := doGet(t, server, "http://deepmap.ai/protected_resource2")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	r.HandleFunc("/protected_resource_401", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	// Call a protected function without credentials
	{
		rec := doGet(t, server, "http://deepmap.ai/protected_resource_401")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Equal(t, "test: security requirements failed: unauthorized\n", rec.Body.String())
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

}

func testRequestValidatorBasicFunctions(t *testing.T, r *http.ServeMux, mw func(next http.Handler) http.Handler) {
	called := false

	// Install a request handler for /resource. We want to make sure it doesn't
	// get called.
	r.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			called = true
			w.WriteHeader(http.StatusOK)
			return
		} else if r.Method == http.MethodPost {
			called = true
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	server := use(r, mw)

	// Let's send the request to the wrong server, this should return 404
	{
		rec := doGet(t, server, "http://not.deepmap.ai/resource")
		assert.Equal(t, http.StatusNotFound, rec.Code)
		assert.False(t, called, "Handler should not have been called")
	}

	// Let's send a good request, it should pass
	{
		rec := doGet(t, server, "http://deepmap.ai/resource")
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.True(t, called, "Handler should have been called")
		called = false
	}

	// Send an out-of-spec parameter
	{
		rec := doGet(t, server, "http://deepmap.ai/resource?id=500")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	// Send a bad parameter type
	{
		rec := doGet(t, server, "http://deepmap.ai/resource?id=foo")
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}

	called = false
	// Send a good request body
	{
		body := struct {
			Name string `json:"name"`
		}{
			Name: "Marcin",
		}
		rec := doPost(t, server, "http://deepmap.ai/resource", body)
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
		rec := doPost(t, server, "http://deepmap.ai/resource", body)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
		assert.False(t, called, "Handler should not have been called")
		called = false
	}
}