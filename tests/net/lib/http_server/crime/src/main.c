/*
 * Copyright (c) 2023, Meta
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/ztest.h>
#include <zephyr/net/http/client.h>

/*
 * The goals of CRiMe (Compressed Resources in Memory), are:
 *
 * 1. To support serving static http resources with minimal ROM footprint
 * 2. To do so with the least amount of fuss.
 *
 * For goal number 1, we know we can use python to read a file, compress the contents, and write
 * the compressed contents to another file. We can then wrap that python functionality in a cmake
 * wrapper.
 * 
 * For goal number 2, let's try and address the most common use cases listed below
 *
 * a) an html file
 * b) an html file and a client-side js file
 * c) a web root directory, automating as much content generation as possible
 * d) two web root directories, without shared resources
 * e) two web root directories, with shared resources
 *
 * Additionally, we would like to scale the python / cmake content generation from goal 1 to
 * happen for a number of resources, recursing into subdirectories, etc. At this time, there is no
 * requirement to support any kind of 'dot file' (configuration file), so all files can be treated
 * as simple static resources.
 *
 * The resources necessary to support the above uses cases could be something like what is shown
 * below:
 * 
 * ```
 * service-A
 * ├── css
 * │   └── service-A.css
 * ├── index.html
 * └── js
 *     └── service-A.js
 * service-B
 * ├── css
 * │   └── service-B.css
 * ├── index.html
 * └── js
 *     └── service-B.js
 * shared
 * └── 404.html
 * ```
 *
 * Testing each of these use cases will involve one or more successful HTTP GET requests, with
 * content validation for each request.
 */

static struct http_request req;
static uint8_t buf[CONFIG_TEST_BUF_SIZE];

static void test_nada_cb(struct http_response *rsp,
				   enum http_final_call final_data,
				   void *user_data)
{

}

static void http_client_req_create(const char *url, http_response_cb_t cb)
{
    req = (struct http_request){
        .method = HTTP_GET,
        .url = url,
        .host = CONFIG_TEST_SERVER_ADDR,
        .protocol = CONFIG_TEST_HTTP_PROTO,
        .response = test_nada_cb,
        .recv_buf = buf,
        .recv_buf_len = sizeof(buf),
    };
}

ZTEST(http_server_CRiMe, test_index_html) {

    http_client_req_create("/index.html");

    ret = http_client_req(sock4, &req, timeout, "IPv4 POST");

}

ZTEST_SUITE(http_server_CRiMe, NULL, NULL, NULL, NULL, NULL);
