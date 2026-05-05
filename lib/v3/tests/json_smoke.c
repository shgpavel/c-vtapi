/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../json.h"

#define CHECK(expr)                                                            \
	do {                                                                   \
		if (!(expr)) {                                                 \
			fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, \
			        __LINE__, #expr);                              \
			return 1;                                              \
		}                                                              \
	} while (0)

int main(void) {
	static const char fixture[] =
	    "{\"data\":{\"id\":\"example.com\",\"type\":\"domain\","
	    "\"attributes\":{\"registrar\":\"Example Registrar\","
	    "\"reputation\":17,\"malicious\":false,\"score\":4.5},"
	    "\"relationships\":{\"comments\":{\"data\":[]}},"
	    "\"links\":{\"self\":\"https://www.virustotal.com/api/v3/domains/"
	    "example.com\"}}}";
	static const char error_fixture[] =
	    "{\"error\":{\"code\":\"NotFoundError\",\"message\":\"missing\"}}";

	vt_status status = VT_UNKNOWN;
	vt_json* json = vt_json_parse(fixture, sizeof(fixture) - 1, &status);
	CHECK(status == VT_OK);
	CHECK(json != NULL);
	CHECK(vt_json_stringify(json) != NULL);

	vt_object* object = vt_json_to_object(json);
	CHECK(object != NULL);
	CHECK(strcmp(vt_object_id(object), "example.com") == 0);
	CHECK(strcmp(vt_object_type(object), "domain") == 0);
	CHECK(vt_object_attribute_count(object) == 4);
	CHECK(vt_object_relationship_count(object) == 1);
	CHECK(vt_object_link_count(object) == 1);
	CHECK(strcmp(vt_object_attributes_get_str(object, "registrar"),
	             "Example Registrar") == 0);
	CHECK(strcmp(vt_object_attribute(object, "reputation"), "17") == 0);
	CHECK(strcmp(vt_object_links_get_str(object, "self"),
	             "https://www.virustotal.com/api/v3/domains/example.com") ==
	      0);

	int64_t reputation = 0;
	bool malicious = true;
	double score = 0.0;
	CHECK(vt_object_attributes_get_int(object, "reputation", &reputation));
	CHECK(reputation == 17);
	CHECK(vt_object_attributes_get_bool(object, "malicious", &malicious));
	CHECK(!malicious);
	CHECK(vt_object_attributes_get_double(object, "score", &score));
	CHECK(score == 4.5);

	vt_object* comments = vt_object_relationships_get(object, "comments");
	CHECK(comments != NULL);
	CHECK(strcmp(vt_object_relationship(object, "comments"),
	             "{\"data\":[]}") == 0);
	vt_object_free(comments);
	vt_object_free(object);
	vt_json_free(json);

	status = VT_OK;
	json = vt_json_parse(error_fixture, sizeof(error_fixture) - 1, &status);
	CHECK(json == NULL);
	CHECK(status == VT_NOT_FOUND);

	size_t body_len = 0;
	char* body = vt_json_build_comment("hello", &body_len, &status);
	CHECK(status == VT_OK);
	CHECK(body != NULL);
	CHECK(body_len == strlen(body));
	CHECK(strcmp(body,
	             "{\"data\":{\"type\":\"comment\",\"attributes\":{\"text\":"
	             "\"hello\"}}}") == 0);
	vt_json_buffer_free(body);

	return 0;
}
