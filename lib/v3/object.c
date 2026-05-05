/* SPDX-License-Identifier: Apache-2.0 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "json.h"

static yyjson_val* vt_object_section(const vt_object* object,
                                     const char* section) {
	if (object == NULL || section == NULL ||
	    !yyjson_is_obj(object->value)) {
		return NULL;
	}

	yyjson_val* value = yyjson_obj_get(object->value, section);
	return yyjson_is_obj(value) ? value : NULL;
}

static yyjson_val* vt_object_section_get(const vt_object* object,
                                         const char* section,
                                         const char* name) {
	if (name == NULL) {
		return NULL;
	}

	yyjson_val* parent = vt_object_section(object, section);
	return parent == NULL ? NULL : yyjson_obj_get(parent, name);
}

static const char* vt_object_value_string(const vt_object* object,
                                          yyjson_val* value) {
	if (object == NULL || value == NULL) {
		return NULL;
	}
	if (yyjson_is_str(value)) {
		return yyjson_get_str(value);
	}
	if (yyjson_is_raw(value)) {
		return yyjson_get_raw(value);
	}

	vt_object* mutable_object = (vt_object*)object;
	free(mutable_object->scratch);
	mutable_object->scratch =
	    yyjson_val_write(value, YYJSON_WRITE_NOFLAG, NULL);
	return mutable_object->scratch;
}

vt_object* vt_object_from_value(vt_json_doc* doc, yyjson_val* value) {
	if (doc == NULL || value == NULL) {
		return NULL;
	}

	vt_object* object = malloc(sizeof(*object));
	if (object == NULL) {
		return NULL;
	}

	object->doc = vt_json_doc_ref(doc);
	object->value = value;
	object->scratch = NULL;
	return object;
}

void vt_object_free(vt_object* object) {
	if (object == NULL) {
		return;
	}

	vt_json_doc_unref(object->doc);
	free(object->scratch);
	free(object);
}

const char* vt_object_id(const vt_object* object) {
	if (object == NULL || !yyjson_is_obj(object->value)) {
		return NULL;
	}

	yyjson_val* id = yyjson_obj_get(object->value, "id");
	return yyjson_is_str(id) ? yyjson_get_str(id) : NULL;
}

const char* vt_object_type(const vt_object* object) {
	if (object == NULL || !yyjson_is_obj(object->value)) {
		return NULL;
	}

	yyjson_val* type = yyjson_obj_get(object->value, "type");
	return yyjson_is_str(type) ? yyjson_get_str(type) : NULL;
}

const char* vt_object_attribute(const vt_object* object, const char* name) {
	return vt_object_value_string(
	    object, vt_object_section_get(object, "attributes", name));
}

const char* vt_object_relationship(const vt_object* object, const char* name) {
	return vt_object_value_string(
	    object, vt_object_section_get(object, "relationships", name));
}

const char* vt_object_link(const vt_object* object, const char* name) {
	return vt_object_value_string(
	    object, vt_object_section_get(object, "links", name));
}

size_t vt_object_attribute_count(const vt_object* object) {
	return yyjson_obj_size(vt_object_section(object, "attributes"));
}

size_t vt_object_relationship_count(const vt_object* object) {
	return yyjson_obj_size(vt_object_section(object, "relationships"));
}

size_t vt_object_link_count(const vt_object* object) {
	return yyjson_obj_size(vt_object_section(object, "links"));
}

const char* vt_object_attributes_get_str(const vt_object* object,
                                         const char* name) {
	yyjson_val* value = vt_object_section_get(object, "attributes", name);
	return yyjson_is_str(value) ? yyjson_get_str(value) : NULL;
}

bool vt_object_attributes_get_int(const vt_object* object, const char* name,
                                  int64_t* out) {
	if (out == NULL) {
		return false;
	}

	yyjson_val* value = vt_object_section_get(object, "attributes", name);
	if (yyjson_is_sint(value)) {
		*out = yyjson_get_sint(value);
		return true;
	}
	if (yyjson_is_uint(value) && yyjson_get_uint(value) <= INT64_MAX) {
		*out = (int64_t)yyjson_get_uint(value);
		return true;
	}

	return false;
}

bool vt_object_attributes_get_bool(const vt_object* object, const char* name,
                                   bool* out) {
	if (out == NULL) {
		return false;
	}

	yyjson_val* value = vt_object_section_get(object, "attributes", name);
	if (!yyjson_is_bool(value)) {
		return false;
	}

	*out = yyjson_get_bool(value);
	return true;
}

bool vt_object_attributes_get_double(const vt_object* object, const char* name,
                                     double* out) {
	if (out == NULL) {
		return false;
	}

	yyjson_val* value = vt_object_section_get(object, "attributes", name);
	if (!yyjson_is_num(value)) {
		return false;
	}

	*out = yyjson_get_num(value);
	return true;
}

vt_object* vt_object_relationships_get(const vt_object* object,
                                       const char* name) {
	if (object == NULL) {
		return NULL;
	}

	yyjson_val* value =
	    vt_object_section_get(object, "relationships", name);
	return value == NULL ? NULL : vt_object_from_value(object->doc, value);
}

const char* vt_object_links_get_str(const vt_object* object, const char* name) {
	yyjson_val* value = vt_object_section_get(object, "links", name);
	return yyjson_is_str(value) ? yyjson_get_str(value) : NULL;
}
