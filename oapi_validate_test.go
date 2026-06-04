package nethttpmiddleware

import (
	"fmt"
	"testing"

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
