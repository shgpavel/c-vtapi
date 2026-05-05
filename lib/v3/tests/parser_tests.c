/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../json.h"
#include "../page.h"

#define FILE_SHA256                                                            \
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
#define URL_ID                                                                 \
	"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

#define CHECK(expr)                                                            \
	do {                                                                   \
		if (!(expr)) {                                                 \
			fprintf(stderr, "check failed: %s:%d: %s\n", __FILE__, \
			        __LINE__, #expr);                              \
			return 1;                                              \
		}                                                              \
	} while (0)

#define CHECK_STREQ(actual, expected)                                          \
	do {                                                                   \
		const char* check_actual = (actual);                           \
		const char* check_expected = (expected);                       \
		if (check_actual == NULL ||                                   \
		    strcmp(check_actual, check_expected) != 0) {               \
			fprintf(stderr,                                         \
			        "check failed: %s:%d: %s == %s (got %s)\n",    \
			        __FILE__, __LINE__, #actual, #expected,        \
			        check_actual == NULL ? "(null)"                \
			                             : check_actual);          \
			return 1;                                              \
		}                                                              \
	} while (0)

static char* copy_string(const char* value) {
	const size_t len = strlen(value);
	char* copy = malloc(len + 1);
	if (copy == NULL) {
		return NULL;
	}

	memcpy(copy, value, len + 1);
	return copy;
}

static char* join_path(const char* dir, const char* name) {
	const size_t dir_len = strlen(dir);
	const size_t name_len = strlen(name);
	const bool need_sep = dir_len > 0 && dir[dir_len - 1] != '/';

	char* path = malloc(dir_len + (need_sep ? 1U : 0U) + name_len + 1U);
	if (path == NULL) {
		return NULL;
	}

	memcpy(path, dir, dir_len);
	size_t offset = dir_len;
	if (need_sep) {
		path[offset] = '/';
		offset++;
	}
	memcpy(path + offset, name, name_len + 1U);
	return path;
}

static bool file_readable(const char* path) {
	FILE* file = fopen(path, "rb");
	if (file == NULL) {
		return false;
	}

	fclose(file);
	return true;
}

static bool fixture_dir_is_valid(const char* dir) {
	char* path = join_path(dir, "file_report.json");
	if (path == NULL) {
		return false;
	}

	const bool valid = file_readable(path);
	free(path);
	return valid;
}

static char* source_fixture_dir(void) {
	const char* source = __FILE__;
	const char* slash = strrchr(source, '/');
	if (slash == NULL) {
		return copy_string("fixtures");
	}

	const size_t source_dir_len = (size_t)(slash - source);
	static const char suffix[] = "/fixtures";
	const size_t suffix_len = sizeof(suffix) - 1U;
	char* dir = malloc(source_dir_len + suffix_len + 1U);
	if (dir == NULL) {
		return NULL;
	}

	memcpy(dir, source, source_dir_len);
	memcpy(dir + source_dir_len, suffix, suffix_len + 1U);
	return dir;
}

static char* choose_fixture_dir(int argc, char** argv) {
	if (argc > 1 && argv[1][0] != '\0') {
		char* dir = copy_string(argv[1]);
		if (dir == NULL || fixture_dir_is_valid(dir)) {
			return dir;
		}
		free(dir);
	}

	const char* env_dir = getenv("VT_PARSER_FIXTURES_DIR");
	if (env_dir != NULL && env_dir[0] != '\0') {
		char* dir = copy_string(env_dir);
		if (dir == NULL || fixture_dir_is_valid(dir)) {
			return dir;
		}
		free(dir);
	}

	char* dir = source_fixture_dir();
	if (dir == NULL || fixture_dir_is_valid(dir)) {
		return dir;
	}
	free(dir);

	dir = copy_string("lib/v3/tests/fixtures");
	if (dir == NULL || fixture_dir_is_valid(dir)) {
		return dir;
	}
	free(dir);

	dir = copy_string("../lib/v3/tests/fixtures");
	if (dir == NULL || fixture_dir_is_valid(dir)) {
		return dir;
	}
	free(dir);

	return NULL;
}

static char* read_fixture(const char* fixture_dir, const char* name,
                          size_t* out_len) {
	*out_len = 0;
	char* path = join_path(fixture_dir, name);
	if (path == NULL) {
		return NULL;
	}

	FILE* file = fopen(path, "rb");
	if (file == NULL) {
		fprintf(stderr, "failed to open fixture: %s\n", path);
		free(path);
		return NULL;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		fprintf(stderr, "failed to seek fixture: %s\n", path);
		fclose(file);
		free(path);
		return NULL;
	}

	const long file_len = ftell(file);
	if (file_len < 0) {
		fprintf(stderr, "failed to size fixture: %s\n", path);
		fclose(file);
		free(path);
		return NULL;
	}
	rewind(file);

	char* buffer = malloc((size_t)file_len + 1U);
	if (buffer == NULL) {
		fclose(file);
		free(path);
		return NULL;
	}

	const size_t len = (size_t)file_len;
	if (fread(buffer, 1, len, file) != len) {
		fprintf(stderr, "failed to read fixture: %s\n", path);
		free(buffer);
		fclose(file);
		free(path);
		return NULL;
	}

	buffer[len] = '\0';
	*out_len = len;
	fclose(file);
	free(path);
	return buffer;
}

static int test_file_report(const char* fixture_dir) {
	size_t body_len = 0;
	char* body = read_fixture(fixture_dir, "file_report.json", &body_len);
	CHECK(body != NULL);

	vt_status status = VT_UNKNOWN;
	vt_json* json = vt_json_parse(body, body_len, &status);
	CHECK(status == VT_OK);
	CHECK(json != NULL);

	vt_object* object = vt_json_to_object(json);
	CHECK(object != NULL);
	CHECK_STREQ(vt_object_id(object), FILE_SHA256);
	CHECK_STREQ(vt_object_type(object), "file");

	int64_t size = 0;
	CHECK(vt_object_attributes_get_int(object, "size", &size));
	CHECK(size == 12345);

	vt_object_free(object);
	vt_json_free(json);
	free(body);
	return 0;
}

static int test_url_report(const char* fixture_dir) {
	size_t body_len = 0;
	char* body = read_fixture(fixture_dir, "url_report.json", &body_len);
	CHECK(body != NULL);

	vt_status status = VT_UNKNOWN;
	vt_json* json = vt_json_parse(body, body_len, &status);
	CHECK(status == VT_OK);
	CHECK(json != NULL);

	vt_object* object = vt_json_to_object(json);
	CHECK(object != NULL);
	CHECK_STREQ(vt_object_id(object), URL_ID);
	CHECK_STREQ(vt_object_type(object), "url");
	CHECK_STREQ(vt_object_attributes_get_str(object, "url"),
	            "https://example.com/");

	int64_t response_code = 0;
	CHECK(vt_object_attributes_get_int(object, "last_http_response_code",
	                                   &response_code));
	CHECK(response_code == 200);

	vt_object_free(object);
	vt_json_free(json);
	free(body);
	return 0;
}

static int test_relationship_page(const char* fixture_dir) {
	size_t body_len = 0;
	char* body =
	    read_fixture(fixture_dir, "file_relationship_page.json", &body_len);
	CHECK(body != NULL);

	vt_status status = VT_UNKNOWN;
	vt_json* json = vt_json_parse(body, body_len, &status);
	CHECK(status == VT_OK);
	CHECK(json != NULL);
	vt_json_free(json);

	vt_http_response response = {
	    .status_code = 200,
	    .body = body,
	    .body_len = body_len,
	};
	vt_object** objects = NULL;
	size_t count = 0;
	char* next_url = NULL;
	char* cursor = NULL;
	status = vt_page_parse_objects(&response, &objects, &count, &next_url,
	                               &cursor, NULL);
	CHECK(status == VT_OK);
	CHECK(objects != NULL);
	CHECK(count == 2);
	CHECK_STREQ(vt_object_id(objects[0]), "example.com");
	CHECK_STREQ(vt_object_type(objects[0]), "domain");
	CHECK_STREQ(vt_object_id(objects[1]), "93.184.216.34");
	CHECK_STREQ(vt_object_type(objects[1]), "ip_address");
	CHECK_STREQ(cursor, "eyJsaW1pdCI6Miwib2Zmc2V0IjoyfQ");
	CHECK_STREQ(
	    next_url,
	    "https://www.virustotal.com/api/v3/files/" FILE_SHA256
	    "/contacted_domains?cursor=eyJsaW1pdCI6Miwib2Zmc2V0IjoyfQ");

	for (size_t i = 0; i < count; i++) {
		vt_object_free(objects[i]);
	}
	free(objects);
	free(next_url);
	free(cursor);
	free(body);
	return 0;
}

static int test_error_fixture(const char* fixture_dir, const char* name,
                              vt_status expected_status) {
	size_t body_len = 0;
	char* body = read_fixture(fixture_dir, name, &body_len);
	CHECK(body != NULL);

	vt_status status = VT_OK;
	vt_json* json = vt_json_parse(body, body_len, &status);
	CHECK(json == NULL);
	CHECK(status == expected_status);

	free(body);
	return 0;
}

int main(int argc, char** argv) {
	char* fixture_dir = choose_fixture_dir(argc, argv);
	CHECK(fixture_dir != NULL);

	int status = test_file_report(fixture_dir);
	if (status == 0) {
		status = test_url_report(fixture_dir);
	}
	if (status == 0) {
		status = test_relationship_page(fixture_dir);
	}
	if (status == 0) {
		status =
		    test_error_fixture(fixture_dir, "error_not_found.json",
		                       VT_NOT_FOUND);
	}
	if (status == 0) {
		status =
		    test_error_fixture(fixture_dir, "error_quota.json",
		                       VT_RATE_LIMIT);
	}

	free(fixture_dir);
	return status;
}
