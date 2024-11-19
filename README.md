# dis-authentication-stub

This project provides an authentication service stub for testing login and authentication processes without relying on `dp-identity-api`, `Florence`, or `Cognito`. The `dis-authentication-stub` simulates essential login, token renewal, and proxy functionality, allowing local testing for services such as dp-dataset-api when running in "private endpoints enabled" mode.

## Getting started

To run the service locally:

* Run `make debug` to run application on <http://localhost:29500>

Additional Commands:

* Run `make help` to see full list of make targets
* Run `make prep` to decrypt the necessary files to run the service

### Dependencies

* No further dependencies other than those defined in `go.mod`

### Endpoints and Functionalities

This stub provides the following endpoints to facilitate testing of authentication workflows:

1. Health Check

   * GET /health: Returns 200 OK to confirm the service is running.

2. Login Simulation

    * GET /florence/login: Displays a form with a list of configured users. Accepts an optional redirect query parameter (default is /florence/collections).

    * POST /florence/login: Processes the form submission, setting the following cookies:
        * access_token: Signed JWT for the selected user.
        * id_token: Signed JWT for the selected user.
        * refresh_token: Random opaque token stored in memory.

3. Token Management

    * DELETE /tokens/self: Logs out the user by removing session entries and expiring the id_token, access_token, and refresh_token cookies.

    * PUT /tokens/self: Reads the refresh_token cookie to renew the access and ID tokens if valid. Returns 400 if missing or 403 if expired.

4. JWT Key Retrieval

    * GET /jwt-keys: Returns a JSON map of public JWT signing keys, matching the format of dp-identity-api.

5. API Reverse Proxy

    * /api/: Proxies requests to APIs and sets the Authorization header with the access_token cookie value.

6. Service Identity Validation

    * GET /identity: Verifies the service token in the Authorization header. Returns the app ID if valid, or 403 Forbidden otherwise.

### Configuration

| Environment variable         | Default                 | Description                                                                                                        |
|------------------------------|-------------------------|--------------------------------------------------------------------------------------------------------------------|
| API_VERSIONS                 | "", "v1"                | To provision for versioned API endpoints                                                                           |
| BIND_ADDR                    | :29500                  | The host and port to bind to                                                                                       |
| GRACEFUL_SHUTDOWN_TIMEOUT    | 5s                      | The graceful shutdown timeout in seconds (`time.Duration` format)                                                  |
| HEALTHCHECK_INTERVAL         | 30s                     | Time between self-healthchecks (`time.Duration` format)                                                            |
| HEALTHCHECK_CRITICAL_TIMEOUT | 90s                     | Time to wait until an unhealthy dependent propagates its state to make this app unhealthy (`time.Duration` format) |
| OTEL_EXPORTER_OTLP_ENDPOINT  | localhost:4317          | Endpoint for OpenTelemetry service                                                                                 |
| OTEL_SERVICE_NAME            | dis-authentication-stub | Label of service for OpenTelemetry service                                                                         |
| OTEL_BATCH_TIMEOUT           | 5s                      | Timeout for OpenTelemetry                                                                                          |
| OTEL_ENABLED                 | false                   | Feature flag to enable OpenTelemetry                                                                               |

### Contributing

See [CONTRIBUTING](CONTRIBUTING.md) for details.

### License

Copyright © 2024, Office for National Statistics (https://www.ons.gov.uk)

Released under MIT license, see [LICENSE](LICENSE.md) for details.
