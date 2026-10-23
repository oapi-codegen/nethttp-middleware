package nethttpmiddleware

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
)

func Test_determineStatusCodeForMultiError(t *testing.T) {
	t.Run("returns HTTP 400 Bad Request when only `RequestError`s", func(t *testing.T) {
		errs := []error{
			&openapi3filter.RequestError{},
			&openapi3filter.RequestError{},
		}

		expected := 400
		actual := determineStatusCodeForMultiError(errs)

		if expected != actual {
			t.Errorf("Expected an HTTP %d to be returned, but received %d", expected, actual)
		}
	})

	t.Run("returns HTTP 401 Unauthorized when only `SecurityRequirementsError`s", func(t *testing.T) {
		errs := []error{
			&openapi3filter.SecurityRequirementsError{},
			&openapi3filter.SecurityRequirementsError{},
		}

		expected := 401
		actual := determineStatusCodeForMultiError(errs)

		if expected != actual {
			t.Errorf("Expected an HTTP %d to be returned, but received %d", expected, actual)
		}
	})

	t.Run("returns HTTP 500 Internal Server Error when mixed error types", func(t *testing.T) {
		errs := []error{
			&openapi3filter.RequestError{},
			&openapi3filter.SecurityRequirementsError{},
		}

		expected := 500
		actual := determineStatusCodeForMultiError(errs)

		if expected != actual {
			t.Errorf("Expected an HTTP %d to be returned, but received %d", expected, actual)
		}
	})

	t.Run("returns HTTP 500 Internal Server Error when unknown error type(s) are seen", func(t *testing.T) {
		errs := []error{
			fmt.Errorf("this isn't a known error type"),
		}

		expected := 500
		actual := determineStatusCodeForMultiError(errs)

		if expected != actual {
			t.Errorf("Expected an HTTP %d to be returned, but received %d", expected, actual)
		}
	})
}

const validatedValueSpec = `
openapi: "3.0.0"
info:
  version: 1.0.0
  title: TestServer
paths:
  /resource:
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
`

// validatedValuer is the interface openapi3filter gives the request body when
// openapi3filter.Options.KeepValidatedValue is set.
type validatedValuer interface {
	ValidatedValue() any
}

// bodySeen records what a handler behind the middleware saw on r.Body.
type bodySeen struct {
	called         bool
	hasValue       bool
	validatedValue any
	body           []byte
}

// postThroughValidator sends a POST with body through the middleware built
// from options (nil means OapiRequestValidator) and records the r.Body the
// handler received.
func postThroughValidator(t *testing.T, options *Options, body string) (*httptest.ResponseRecorder, bodySeen) {
	t.Helper()

	spec, err := openapi3.NewLoader().LoadFromData([]byte(validatedValueSpec))
	if err != nil {
		t.Fatalf("failed to load spec: %v", err)
	}

	var seen bodySeen
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.called = true
		if vv, ok := r.Body.(validatedValuer); ok {
			seen.hasValue = true
			seen.validatedValue = vv.ValidatedValue()
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body in handler: %v", err)
		}
		seen.body = data
		w.WriteHeader(http.StatusNoContent)
	})

	var mw func(http.Handler) http.Handler
	if options == nil {
		mw = OapiRequestValidator(spec)
	} else {
		mw = OapiRequestValidatorWithOptions(spec, options)
	}

	req := httptest.NewRequest(http.MethodPost, "/resource", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mw(handler).ServeHTTP(rec, req)

	return rec, seen
}

func TestKeepValidatedValue(t *testing.T) {
	const body = `{"name":"Wilbur"}`
	expectedValue := map[string]any{"name": "Wilbur"}

	keptCases := []struct {
		name    string
		options *Options
	}{
		{
			name:    "OapiRequestValidator without options",
			options: nil,
		},
		{
			name:    "empty Options",
			options: &Options{},
		},
		{
			name: "ErrorHandlerWithOpts",
			options: &Options{
				ErrorHandlerWithOpts: func(_ context.Context, err error, w http.ResponseWriter, _ *http.Request, opts ErrorHandlerOpts) {
					http.Error(w, err.Error(), opts.StatusCode)
				},
			},
		},
	}

	for _, tc := range keptCases {
		t.Run("keeps the validated value with "+tc.name, func(t *testing.T) {
			rec, seen := postThroughValidator(t, tc.options, body)

			if rec.Code != http.StatusNoContent {
				t.Fatalf("expected HTTP %d, got %d: %s", http.StatusNoContent, rec.Code, rec.Body.String())
			}
			if !seen.called {
				t.Fatal("handler was not called")
			}
			if !seen.hasValue {
				t.Fatalf("expected r.Body (%T) to implement ValidatedValue() any", seen.validatedValue)
			}
			if !reflect.DeepEqual(expectedValue, seen.validatedValue) {
				t.Errorf("expected validated value %#v, got %#v", expectedValue, seen.validatedValue)
			}
			if string(seen.body) != body {
				t.Errorf("expected the body to still read %q, got %q", body, string(seen.body))
			}
			if tc.options != nil && tc.options.Options.KeepValidatedValue {
				t.Error("the caller's Options.Options.KeepValidatedValue was modified")
			}
		})
	}

	t.Run("DiscardValidatedValue drops the validated value", func(t *testing.T) {
		options := &Options{
			DiscardValidatedValue: true,
			Options: openapi3filter.Options{
				// overridden by DiscardValidatedValue
				KeepValidatedValue: true,
			},
		}
		rec, seen := postThroughValidator(t, options, body)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected HTTP %d, got %d: %s", http.StatusNoContent, rec.Code, rec.Body.String())
		}
		if !seen.called {
			t.Fatal("handler was not called")
		}
		if seen.hasValue {
			t.Error("expected r.Body not to implement ValidatedValue() any")
		}
		if string(seen.body) != body {
			t.Errorf("expected the body to still read %q, got %q", body, string(seen.body))
		}
		if !options.Options.KeepValidatedValue {
			t.Error("the caller's Options.Options.KeepValidatedValue was modified")
		}
	})

	t.Run("ExcludeRequestBody still passes the body through", func(t *testing.T) {
		options := &Options{
			Options: openapi3filter.Options{
				ExcludeRequestBody: true,
			},
		}
		rec, seen := postThroughValidator(t, options, body)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected HTTP %d, got %d: %s", http.StatusNoContent, rec.Code, rec.Body.String())
		}
		if !seen.called {
			t.Fatal("handler was not called")
		}
		if seen.hasValue {
			t.Error("expected r.Body not to implement ValidatedValue() any when the body is not validated")
		}
		if string(seen.body) != body {
			t.Errorf("expected the body to still read %q, got %q", body, string(seen.body))
		}
	})

	t.Run("an invalid body is still rejected", func(t *testing.T) {
		rec, seen := postThroughValidator(t, nil, `{"name":1}`)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected HTTP %d, got %d: %s", http.StatusBadRequest, rec.Code, rec.Body.String())
		}
		if seen.called {
			t.Error("handler should not have been called")
		}
	})
}
