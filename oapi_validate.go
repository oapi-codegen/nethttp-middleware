// Package middleware implements middleware function for net/http compatible router
// which validates incoming HTTP requests to make sure that they conform to the given OAPI 3.0 specification.
// When OAPI validation fails on the request, we return an HTTP/400.
package nethttpmiddleware

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
)

// ErrorHandler is called when there is an error in validation
type ErrorHandler func(w http.ResponseWriter, message string, statusCode int)

// ErrorHandlerWithOpts is called when there is an error in validation, if found in Options.
// Passes error-handling specific opts over and above the standard error handler.
type ErrorHandlerWithOpts func(w http.ResponseWriter, message string, statusCode int, opts ErrorHandlerOpts)

// ErrorHandlerOpts is used with ErrorHandlerWithOpts()
type ErrorHandlerOpts struct {
	*http.Request
	*routers.Route
	context.Context
	Error error
}

// MultiErrorHandler is called when oapi returns a MultiError type
type MultiErrorHandler func(openapi3.MultiError) (int, error)

// Options to customize request validation, openapi3filter specified options will be passed through.
type Options struct {
	Options              openapi3filter.Options
	ErrorHandler         ErrorHandler
	ErrorHandlerWithOpts ErrorHandlerWithOpts
	MultiErrorHandler    MultiErrorHandler
	// SilenceServersWarning allows silencing a warning for https://github.com/deepmap/oapi-codegen/issues/882 that reports when an OpenAPI spec has `spec.Servers != nil`
	SilenceServersWarning bool
}

// OapiRequestValidator Creates middleware to validate request by swagger spec.
func OapiRequestValidator(swagger *openapi3.T) func(next http.Handler) http.Handler {
	return OapiRequestValidatorWithOptions(swagger, nil)
}

// OapiRequestValidatorWithOptions Creates middleware to validate request by swagger spec.
func OapiRequestValidatorWithOptions(swagger *openapi3.T, options *Options) func(next http.Handler) http.Handler {
	if swagger.Servers != nil && (options == nil || !options.SilenceServersWarning) {
		log.Println("WARN: OapiRequestValidatorWithOptions called with an OpenAPI spec that has `Servers` set. This may lead to an HTTP 400 with `no matching operation was found` when sending a valid request, as the validator performs `Host` header validation. If you're expecting `Host` header validation, you can silence this warning by setting `Options.SilenceServersWarning = true`. See https://github.com/deepmap/oapi-codegen/issues/882 for more information.")
	}

	router, err := gorillamux.NewRouter(swagger)
	if err != nil {
		panic(err)
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// validate request
			if statusCode, route, err := validateRequest(r, router, options); err != nil {
				if options != nil {
					if options.ErrorHandlerWithOpts != nil {
						options.ErrorHandlerWithOpts(w, err.Error(), statusCode, ErrorHandlerOpts{
							Context: r.Context(),
							Request: r,
							Route:   route,
							Error:   err,
						})
						return
					}
					if options.ErrorHandler != nil {
						options.ErrorHandler(w, err.Error(), statusCode)
						return
					}
				}
				http.Error(w, err.Error(), statusCode)
				return
			}

			// serve
			next.ServeHTTP(w, r)
		})
	}

}

// validateRequest is called from the middleware above and actually does the work
// of validating a request.
func validateRequest(r *http.Request, router routers.Router, options *Options) (int, *routers.Route, error) {

	// Find route
	route, pathParams, err := router.FindRoute(r)
	if err != nil {
		return http.StatusNotFound, nil, err // We failed to find a matching route for the request.
	}

	// Validate request
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
	}

	if options != nil {
		requestValidationInput.Options = &options.Options
	}

	if err := openapi3filter.ValidateRequest(r.Context(), requestValidationInput); err != nil {
		me := openapi3.MultiError{}
		if errors.As(err, &me) {
			errFunc := getMultiErrorHandlerFromOptions(options)
			status, err2 := errFunc(me)
			return status, route, err2
		}

		switch e := err.(type) {
		case *openapi3filter.RequestError:
			// We've got a bad request
			// Split up the verbose error by lines and return the first one
			// openapi errors seem to be multi-line with a decent message on the first
			errorLines := strings.Split(e.Error(), "\n")
			return http.StatusBadRequest, route, fmt.Errorf(errorLines[0])
		case *openapi3filter.SecurityRequirementsError:
			return http.StatusUnauthorized, route, err
		default:
			// This should never happen today, but if our upstream code changes,
			// we don't want to crash the server, so handle the unexpected error.
			return http.StatusInternalServerError, route, fmt.Errorf("error validating route: %s", err.Error())
		}
	}

	return http.StatusOK, route, nil
}

// attempt to get the MultiErrorHandler from the options. If it is not set,
// return a default handler
func getMultiErrorHandlerFromOptions(options *Options) MultiErrorHandler {
	if options == nil {
		return defaultMultiErrorHandler
	}

	if options.MultiErrorHandler == nil {
		return defaultMultiErrorHandler
	}

	return options.MultiErrorHandler
}

// defaultMultiErrorHandler returns a StatusBadRequest (400) and a list
// of all the errors. This method is called if there are no other
// methods defined on the options.
func defaultMultiErrorHandler(me openapi3.MultiError) (int, error) {
	return http.StatusBadRequest, me
}
