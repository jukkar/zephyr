# Compressed Resource in Memory (CRiMe) Tests

## Overview
This testsuite demonstrates how to configure Zephyr's HTTP server to serve CRiMe resources.

To illustrate the process, we have two contrived web services.
 * service_A
 * service_B

Both services are mostly identical, aside from some uniquely identifying features.

All of the service_A resources are incorporated into the Zephyr app using the simpler,
scalable, and more automatic cmake function `http_server_generate_crime_res()`.

```shell
service_A/
├── css
│   └── service-A.css
├── error-pages
│   └── four-zero-four.html -> ../../shared/404.html
├── index.html
└── js
    └── service-A.js
```

All of the service_B resources are manually added via C macros and cmake functions such as
`HTTP_RESOURCE_DEFINE()` and `generate_inc_file_for_target()`. This is mainly for illustrative
purposes to show the processes that happen behind the scenes when using
`http_server_generate_crime_res()`.

```shell
service_B/
├── css
│   └── service-B.css
├── index.html
├── js
│   └── service-B.js
└── status-pages
    └── 404.htm -> ../../shared/404.html
```

## Shared Resources

Shared resources have only one instance in ROM but may be referenced by multiple services.