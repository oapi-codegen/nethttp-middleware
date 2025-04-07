# OpenAPI Validation Middleware for `net/http`-compatible servers

An HTTP middleware to perform validation of incoming requests via an OpenAPI specification.

This project is a lightweight wrapper over the excellent [kin-openapi](https://github.com/getkin/kin-openapi) library's [`openapi3filter` package](https://pkg.go.dev/github.com/getkin/kin-openapi/openapi3filter).

This is _intended_ to be used with code that's generated through [`oapi-codegen`](https://github.com/oapi-codegen/oapi-codegen), but should work otherwise.

⚠️ This README may be for the latest development version, which may contain unreleased changes. Please ensure you're looking at the README for the latest release version.

## Usage

```go
# TODO
```

## FAQs

### Which HTTP servers should this work with?

If you're using something that's compliant with `net/http` (which should be all Go web frameworks / routers / HTTP servers) it should work as-is.

We explicitly test with the following servers, as they correspond with versions used by users of [oapi-codegen/oapi-codegen](https://github.com/oapi-codegen/oapi-codegen):

- [Chi](https://github.com/go-chi/chi)
- [gorilla/mux](https://github.com/gorilla/mux)
- [net/http](https://pkg.go.dev/net/http)

### "This doesn't support ..." / "I think it's a bug that ..."

As this project is a lightweight wrapper over [kin-openapi](https://github.com/getkin/kin-openapi)'s [`openapi3filter` package](https://pkg.go.dev/github.com/getkin/kin-openapi/openapi3filter), it's _likely_ that any bugs/features are better sent upstream.

However, it's worth raising an issue here instead, as it'll allow us to triage it before it goes to the kin-openapi maintainers.

Additionally, as `oapi-codegen` contains [a number of middleware modules](https://github.com/search?q=org%3Aoapi-codegen+middleware&type=repositories), we'll very likely want to implement the same functionality across all the middlewares, so it may take a bit more coordination to get the changes in across our middlewares.

### I've just updated my version of `kin-openapi`, and now I can't build my code 😠

The [kin-openapi](https://github.com/getkin/kin-openapi) project - which we 💜 for providing a great library and set of tooling for interacting with OpenAPI - is a pre-v1 release, which means that they're within their rights to push breaking changes.

This may lead to breakage in your consuming code, and if so, sorry that's happened!

We'll be aware of the issue, and will work to update both the core `oapi-codegen` and the middlewares accordingly.
