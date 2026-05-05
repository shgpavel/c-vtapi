/* SPDX-License-Identifier: Apache-2.0 */

#include <stddef.h>
#include <vt/object.h>

struct vt_object {
	unsigned int reserved;
};

void vt_object_free(vt_object* object) {
	(void)object;
	/* TODO: Release object envelope state. */
}

const char* vt_object_id(const vt_object* object) {
	(void)object;
	/* TODO: Return the object id from the v3 envelope. */
	return NULL;
}

const char* vt_object_type(const vt_object* object) {
	(void)object;
	/* TODO: Return the object type from the v3 envelope. */
	return NULL;
}

const char* vt_object_attribute(const vt_object* object, const char* name) {
	(void)object;
	(void)name;
	/* TODO: Return a raw attribute value by name. */
	return NULL;
}

const char* vt_object_relationship(const vt_object* object, const char* name) {
	(void)object;
	(void)name;
	/* TODO: Return a raw relationship value by name. */
	return NULL;
}

const char* vt_object_link(const vt_object* object, const char* name) {
	(void)object;
	(void)name;
	/* TODO: Return a link value by name. */
	return NULL;
}

size_t vt_object_attribute_count(const vt_object* object) {
	(void)object;
	/* TODO: Count attributes in the v3 envelope. */
	return 0;
}

size_t vt_object_relationship_count(const vt_object* object) {
	(void)object;
	/* TODO: Count relationships in the v3 envelope. */
	return 0;
}

size_t vt_object_link_count(const vt_object* object) {
	(void)object;
	/* TODO: Count links in the v3 envelope. */
	return 0;
}
