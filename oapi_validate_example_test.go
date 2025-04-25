package nethttpmiddleware_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"

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
	fmt.Println("# A request with an invalid HTTP method, to a valid path, is rejected with an HTTP 405 Method Not Allowed")
	body = map[string]string{
		"invalid": "not expected",
	}

	data, err = json.Marshal(body)
	must(err)

	req, err = http.NewRequest(http.MethodPatch, "/resource", bytes.NewReader(data))
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr = httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 405\n", rr.Code)
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
	// # A request with an invalid HTTP method, to a valid path, is rejected with an HTTP 405 Method Not Allowed
	// Received an HTTP 405 response. Expected HTTP 405
	// Response body: method not allowed
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

func ExampleOapiRequestValidatorWithOptions_withErrorHandlerWithOpts() {
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
                id:
                  type: string
                  minLength: 100
                name:
                  type: string
                  enum:
                  - Marcin
              additionalProperties: false
  /protected_resource:
    get:
      operationId: getProtectedResource
      security:
        - BearerAuth:
            - someScope
        - BasicAuth: []
      responses:
        '204':
          description: no content
components:
  securitySchemes:
    BearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT
    BasicAuth:
      type: http
      scheme: basic
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

	errorHandlerFunc := func(ctx context.Context, w http.ResponseWriter, r *http.Request, opts middleware.ErrorHandlerOpts) {
		err := opts.Error

		if opts.MatchedRoute == nil {
			fmt.Printf("ErrorHandlerWithOpts: An HTTP %d was returned by the middleware with error message: %s\n", opts.StatusCode, err.Error())

			// NOTE that you may want to override the default (an HTTP 400 Bad Request) to an HTTP 404 Not Found (or maybe an HTTP 405 Method Not Allowed, depending on what the requested resource was)
			http.Error(w, fmt.Sprintf("No route was found (according to ErrorHandlerWithOpts), and we changed the HTTP status code to %d", http.StatusNotFound), http.StatusNotFound)
			return
		}

		switch e := err.(type) {
		case *openapi3filter.SecurityRequirementsError:
			out := fmt.Sprintf("A SecurityRequirementsError was returned when attempting to authenticate the request to %s %s against %d Security Schemes: %s\n", opts.MatchedRoute.Route.Method, opts.MatchedRoute.Route.Path, len(e.SecurityRequirements), e.Error())
			for _, sr := range e.SecurityRequirements {
				for k, v := range sr {
					out += fmt.Sprintf("- %s: %v\n", k, v)
				}
			}

			fmt.Printf("ErrorHandlerWithOpts: %s\n", out)

			http.Error(w, "You're not allowed!", opts.StatusCode)
			return
		case *openapi3filter.RequestError:
			out := fmt.Sprintf("A RequestError was returned when attempting to validate the request to %s %s: %s\n", opts.MatchedRoute.Route.Method, opts.MatchedRoute.Route.Path, e.Error())

			if e.RequestBody != nil {
				out += "This operation has a request body, which was "
				if !e.RequestBody.Required {
					out += "not "
				}
				out += "required\n"
			}

			if childErr := e.Unwrap(); childErr != nil {
				out += "There was a child error, which was "
				switch e := childErr.(type) {
				case *openapi3.SchemaError:
					out += "a SchemaError, which failed to validate on the " + e.SchemaField + " field"
				default:
					out += "an unknown type (" + reflect.TypeOf(e).String() + ")"
				}
			}

			fmt.Printf("ErrorHandlerWithOpts: %s\n", out)

			http.Error(w, "A bad request was made - but I'm not going to tell you where or how", opts.StatusCode)
			return
		}

		http.Error(w, err.Error(), opts.StatusCode)
	}

	// create middleware
	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Options: openapi3filter.Options{
			AuthenticationFunc: authenticationFunc,
		},
		ErrorHandlerWithOpts: errorHandlerFunc,
	})

	// then wire it in
	server := use(router, mw)

	// ================================================================================
	fmt.Println("# A request that is malformed is rejected with HTTP 400 Bad Request (with no request body), and is then logged by the ErrorHandlerWithOpts")

	req, err := http.NewRequest(http.MethodPost, "/resource", nil)
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 400\n", rr.Code)
	logResponseBody(rr)
	fmt.Println()

	// ================================================================================
	fmt.Println("# A request that is malformed is rejected with HTTP 400 Bad Request (with an invalid request body), and is then logged by the ErrorHandlerWithOpts")

	body := map[string]string{
		"id": "not-long-enough",
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
	fmt.Println("# A request that to an unknown path is rejected with HTTP 404 Not Found, and is then logged by the ErrorHandlerWithOpts")

	req, err = http.NewRequest(http.MethodGet, "/not-a-real-path", nil)
	must(err)

	rr = httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 404\n", rr.Code)
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
	// # A request that is malformed is rejected with HTTP 400 Bad Request (with no request body), and is then logged by the ErrorHandlerWithOpts
	// ErrorHandlerWithOpts: A RequestError was returned when attempting to validate the request to POST /resource: request body has an error: value is required but missing
	// This operation has a request body, which was required
	// There was a child error, which was an unknown type (*errors.errorString)
	// Received an HTTP 400 response. Expected HTTP 400
	// Response body: A bad request was made - but I'm not going to tell you where or how
	//
	// # A request that is malformed is rejected with HTTP 400 Bad Request (with an invalid request body), and is then logged by the ErrorHandlerWithOpts
	// ErrorHandlerWithOpts: A RequestError was returned when attempting to validate the request to POST /resource: request body has an error: doesn't match schema: Error at "/id": minimum string length is 100
	// Schema:
	//   {
	//     "minLength": 100,
	//     "type": "string"
	//   }
	//
	// Value:
	//   "not-long-enough"
	//
	// This operation has a request body, which was required
	// There was a child error, which was a SchemaError, which failed to validate on the minLength field
	// Received an HTTP 400 response. Expected HTTP 400
	// Response body: A bad request was made - but I'm not going to tell you where or how
	//
	// # A request that to an unknown path is rejected with HTTP 404 Not Found, and is then logged by the ErrorHandlerWithOpts
	// ErrorHandlerWithOpts: An HTTP 404 was returned by the middleware with error message: no matching operation was found
	// Received an HTTP 404 response. Expected HTTP 404
	// Response body: No route was found (according to ErrorHandlerWithOpts), and we changed the HTTP status code to 404
	//
	// # A request to an authenticated endpoint must go through an `AuthenticationFunc`, and if it fails, an HTTP 401 is returned
	// `AuthenticationFunc` was called for securitySchemeName=BearerAuth
	// `AuthenticationFunc` was called for securitySchemeName=BasicAuth
	// ErrorHandlerWithOpts: A SecurityRequirementsError was returned when attempting to authenticate the request to GET /protected_resource against 2 Security Schemes: security requirements failed: this check always fails - don't let anyone in! | this check always fails - don't let anyone in!
	// - BearerAuth: [someScope]
	// - BasicAuth: []
	//
	// Received an HTTP 401 response. Expected HTTP 401
	// Response body: You're not allowed!
}

func ExampleOapiRequestValidatorWithOptions_withErrorHandlerWithOptsAndMultiError() {
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
                id:
                  type: string
                  minLength: 100
                name:
                  type: string
                  enum:
                  - Marcin
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

	errorHandlerFunc := func(ctx context.Context, w http.ResponseWriter, r *http.Request, opts middleware.ErrorHandlerOpts) {
		err := opts.Error

		if opts.MatchedRoute == nil {
			fmt.Printf("ErrorHandlerWithOpts: An HTTP %d was returned by the middleware with error message: %s\n", opts.StatusCode, err.Error())

			// NOTE that you may want to override the default (an HTTP 400 Bad Request) to an HTTP 404 Not Found (or maybe an HTTP 405 Method Not Allowed, depending on what the requested resource was)
			http.Error(w, fmt.Sprintf("No route was found (according to ErrorHandlerWithOpts), and we changed the HTTP status code to %d", http.StatusNotFound), http.StatusNotFound)
			return
		}

		switch e := err.(type) {
		// NOTE that when it's a MultiError, there's more work needed here
		case openapi3.MultiError:
			var re *openapi3filter.RequestError
			if e.As(&re) {
				out := fmt.Sprintf("A MultiError was encountered, which contained a RequestError: %s", re)

				if re.Err != nil {
					out += ", which inside it has a error of type (" + reflect.TypeOf(e).String() + ")"
				}

				fmt.Printf("ErrorHandlerWithOpts: %s\n", out)

				http.Error(w, "There was a bad request", opts.StatusCode)
				return
			}

			var se *openapi3filter.SecurityRequirementsError
			if e.As(&se) {
				out := fmt.Sprintf("A MultiError was encountered, which contained a SecurityRequirementsError: %s", re)

				if len(se.Errors) > 0 {
					out += fmt.Sprintf(", which contains %d child errors", len(se.Errors))
				}

				fmt.Printf("ErrorHandlerWithOpts: %s\n", out)

				http.Error(w, "There was an unauthorized request", opts.StatusCode)
				return
			}
		}

		http.Error(w, err.Error(), opts.StatusCode)
	}

	// create middleware
	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Options: openapi3filter.Options{
			// make sure that multiple errors in a given request are returned
			MultiError: true,
		},
		ErrorHandlerWithOpts: errorHandlerFunc,
	})

	// then wire it in
	server := use(router, mw)

	// ================================================================================
	fmt.Println("# A request that is malformed is rejected with HTTP 400 Bad Request (with no request body), and is then logged by the ErrorHandlerWithOpts")

	req, err := http.NewRequest(http.MethodPost, "/resource", nil)
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 400\n", rr.Code)
	logResponseBody(rr)
	fmt.Println()

	// ================================================================================
	fmt.Println("# A request that is malformed is rejected with HTTP 400 Bad Request (with an invalid request body, with multiple issues), and is then logged by the ErrorHandlerWithOpts")

	body := map[string]string{
		"id":   "not-long-enough",
		"name": "Jamie",
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

	// Output:
	// # A request that is malformed is rejected with HTTP 400 Bad Request (with no request body), and is then logged by the ErrorHandlerWithOpts
	// ErrorHandlerWithOpts: A MultiError was encountered, which contained a RequestError: request body has an error: value is required but missing, which inside it has a error of type (openapi3.MultiError)
	// Received an HTTP 400 response. Expected HTTP 400
	// Response body: There was a bad request
	//
	// # A request that is malformed is rejected with HTTP 400 Bad Request (with an invalid request body, with multiple issues), and is then logged by the ErrorHandlerWithOpts
	// ErrorHandlerWithOpts: A MultiError was encountered, which contained a RequestError: request body has an error: doesn't match schema: Error at "/id": minimum string length is 100
	// Schema:
	//   {
	//     "minLength": 100,
	//     "type": "string"
	//   }
	//
	// Value:
	//   "not-long-enough"
	//  | Error at "/name": value is not one of the allowed values ["Marcin"]
	// Schema:
	//   {
	//     "enum": [
	//       "Marcin"
	//     ],
	//     "type": "string"
	//   }
	//
	// Value:
	//   "Jamie"
	// , which inside it has a error of type (openapi3.MultiError)
	// Received an HTTP 400 response. Expected HTTP 400
	// Response body: There was a bad request
}

// In the case that your public OpenAPI spec documents an API which does /not/ match your internal API endpoint setup, you may want to set the `Prefix` option to allow rewriting paths
func ExampleOapiRequestValidatorWithOptions_withPrefix() {
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

	// This should be treated as if it's being called with POST /resource
	router.HandleFunc("/public-api/v1/resource", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s /public-api/v1/resource was called\n", r.Method)

		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	router.HandleFunc("/internal-api/v2/resource", func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("%s /internal-api/v2/resource was called\n", r.Method)

		w.WriteHeader(http.StatusMethodNotAllowed)
	})

	// create middleware
	mw := middleware.OapiRequestValidatorWithOptions(spec, &middleware.Options{
		Options: openapi3filter.Options{
			// make sure that multiple errors in a given request are returned
			MultiError: true,
		},
		Prefix: "/public-api/v1/",
	})

	// then wire it in
	server := use(router, mw)

	// ================================================================================
	fmt.Println("# A request that is well-formed is passed through to the Handler")
	body := map[string]string{
		"name": "Jamie",
	}

	data, err := json.Marshal(body)
	must(err)

	req, err := http.NewRequest(http.MethodPost, "/public-api/v1/resource", bytes.NewReader(data))
	must(err)
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	server.ServeHTTP(rr, req)

	fmt.Printf("Received an HTTP %d response. Expected HTTP 204\n", rr.Code)
	logResponseBody(rr)

	// Output:
	// # A request that is well-formed is passed through to the Handler
	// POST /public-api/v1/resource was called
	// Received an HTTP 204 response. Expected HTTP 204
}
