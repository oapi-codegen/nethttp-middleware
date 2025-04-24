package nethttpmiddleware_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	middleware "github.com/oapi-codegen/nethttp-middleware"
)

func ExampleOapiRequestValidatorWithOptions() {
	rawSpec := `
openapi: "3.0.0"
info:
  version: 1.0.0
  title: TestServer
servers:
  - url: http://example.com/
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
              additionalProperties: false
  /protected_resource:
    get:
      operationId: getProtectedResource
      security:
        - BearerAuth:
            - someScope
      responses:
        '204':
          description: no content
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
`

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	use := func(r *http.ServeMux, middlewares ...func(next http.Handler) http.Handler) http.Handler {
		var s http.Handler
		s = r

		for _, mw := range middlewares {
			s = mw(s)
		}

		return s
	}

	logResponseBody := func(rr *httptest.ResponseRecorder) {
		if rr.Result().Body != nil {
			data, _ := io.ReadAll(rr.Result().Body)
			if len(data) > 0 {
				fmt.Printf("Response body: %s", data)
			}
		}
	}

	spec, err := openapi3.NewLoader().LoadFromData([]byte(rawSpec))
	must(err)

	// NOTE that we need to make sure that the `Servers` aren't set, otherwise the OpenAPI validation middleware will validate that the `Host` header (of incoming requests) are targeting known `Servers` in the OpenAPI spec
	// See also: Options#SilenceServersWarning
	spec.Servers = nil

	router := http.NewServeMux()

	router.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s /resource was called\n", r.Method)

		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	router.HandleFunc("/protected_resource", func(w http.ResponseWriter, r *http.Request) {
		// NOTE that we're setting up our `authenticationFunc` (below) to /never/ allow any requests in - so if we get a response from this endpoint, our `authenticationFunc` hasn't correctly worked

		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	authenticationFunc := func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
		fmt.Printf("`AuthenticationFunc` was called for securitySchemeName=%s\n", ai.SecuritySchemeName)
		return fmt.Errorf("this check always fails - don't let anyone in!")
	}

	// create middleware
	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: authenticationFunc,
		},
	})

	// then wire it in
	server := use(router, mw)

	// ================================================================================
	fmt.Println("# A request that is malformed is rejected with HTTP 400 Bad Request (with no request body)")

	req, err := http.NewRequest(http.MethodPost, "/resource", bytes.NewReader(nil))
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 400\n", rr.Code)
	logResponseBody(rr)
	fmt.Println()

	// ================================================================================
	fmt.Println("# A request that is malformed is rejected with HTTP 400 Bad Request (because an invalid property is sent, and we have `additionalProperties: false`)")
	body := map[string]string{
		"invalid": "not expected",
	}

	data, err := json.Marshal(body)
	must(err)

	req, err = http.NewRequest(http.MethodPost, "/resource", bytes.NewReader(data))
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 400\n", rr.Code)
	logResponseBody(rr)
	fmt.Println()

	// ================================================================================
	fmt.Println("# A request that is well-formed is passed through to the Handler")
	body = map[string]string{
		"name": "Jamie",
	}

	data, err = json.Marshal(body)
	must(err)

	req, err = http.NewRequest(http.MethodPost, "/resource", bytes.NewReader(data))
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 204\n", rr.Code)
	logResponseBody(rr)
	fmt.Println()

	// ================================================================================
	fmt.Println("# A request to an authenticated endpoint must go through an `AuthenticationFunc`, and if it fails, an HTTP 401 is returned")

	req, err = http.NewRequest(http.MethodGet, "/protected_resource", nil)
	must(err)

	rr = httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 401\n", rr.Code)
	logResponseBody(rr)
	fmt.Println()

	// Output:
	// # A request that is malformed is rejected with HTTP 400 Bad Request (with no request body)
	// Received an HTTP 400 response. Expected HTTP 400
	// Response body: request body has an error: value is required but missing
	//
	// # A request that is malformed is rejected with HTTP 400 Bad Request (because an invalid property is sent, and we have `additionalProperties: false`)
	// Received an HTTP 400 response. Expected HTTP 400
	// Response body: request body has an error: doesn't match schema: property "invalid" is unsupported
	//
	// # A request that is well-formed is passed through to the Handler
	// POST /resource was called
	// Received an HTTP 204 response. Expected HTTP 204
	//
	// # A request to an authenticated endpoint must go through an `AuthenticationFunc`, and if it fails, an HTTP 401 is returned
	// `AuthenticationFunc` was called for securitySchemeName=BearerAuth
	// Received an HTTP 401 response. Expected HTTP 401
	// Response body: security requirements failed: this check always fails - don't let anyone in!
}

func ExampleOapiRequestValidatorWithOptions_withErrorHandler() {
	rawSpec := `
openapi: "3.0.0"
info:
  version: 1.0.0
  title: TestServer
servers:
  - url: http://example.com/
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
              additionalProperties: false
`

	must := func(err error) {
		if err != nil {
			panic(err)
		}
	}

	use := func(r *http.ServeMux, middlewares ...func(next http.Handler) http.Handler) http.Handler {
		var s http.Handler
		s = r

		for _, mw := range middlewares {
			s = mw(s)
		}

		return s
	}

	logResponseBody := func(rr *httptest.ResponseRecorder) {
		if rr.Result().Body != nil {
			data, _ := io.ReadAll(rr.Result().Body)
			if len(data) > 0 {
				fmt.Printf("Response body: %s", data)
			}
		}
	}

	spec, err := openapi3.NewLoader().LoadFromData([]byte(rawSpec))
	must(err)

	// NOTE that we need to make sure that the `Servers` aren't set, otherwise the OpenAPI validation middleware will validate that the `Host` header (of incoming requests) are targeting known `Servers` in the OpenAPI spec
	// See also: Options#SilenceServersWarning
	spec.Servers = nil

	router := http.NewServeMux()

	router.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s /resource was called\n", r.Method)

		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	authenticationFunc := func(ctx context.Context, ai *openapi3filter.AuthenticationInput) error {
		fmt.Printf("`AuthenticationFunc` was called for securitySchemeName=%s\n", ai.SecuritySchemeName)
		return fmt.Errorf("this check always fails - don't let anyone in!")
	}

	errorHandlerFunc := func(w http.ResponseWriter, message string, statusCode int) {
		fmt.Printf("ErrorHandler: An HTTP %d was returned by the middleware with error message: %s\n", statusCode, message)
		http.Error(w, "This was rewritten by the ErrorHandler", statusCode)
	}

	// create middleware
	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: authenticationFunc,
		},
		ErrorHandler: errorHandlerFunc,
	})

	// then wire it in
	server := use(router, mw)

	// ================================================================================
	fmt.Println("# A request that is malformed is rejected with HTTP 400 Bad Request (with no request body), and is then logged by the ErrorHandler")

	req, err := http.NewRequest(http.MethodPost, "/resource", bytes.NewReader(nil))
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 400\n", rr.Code)
	logResponseBody(rr)

	// Output:
	// # A request that is malformed is rejected with HTTP 400 Bad Request (with no request body), and is then logged by the ErrorHandler
	// ErrorHandler: An HTTP 400 was returned by the middleware with error message: request body has an error: value is required but missing
	// Received an HTTP 400 response. Expected HTTP 400
	// Response body: This was rewritten by the ErrorHandler
}
