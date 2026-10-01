/*
Copyright 2014 VirusTotal S.L. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/* Growable, always NUL-terminated byte buffer with a sticky OOM flag.
 * Callers append freely and check b->oom once at the end. */

#include <stdlib.h>
#include <string.h>

#include "private.h"

static bool reserve(struct vt_buf *b, size_t n) {
	size_t need, cap;
	char *p;

	if (b->oom) return false;
	if (n > SIZE_MAX - 1 - b->len || (b->max && b->len + n > b->max)) {
		b->oom = true;
		return false;
	}
	need = b->len + n + 1;
	if (need <= b->cap) return true;
	cap = b->cap ? b->cap : 64;
	while (cap < need) cap = cap > SIZE_MAX / 2 ? need : cap * 2;
	p = realloc(b->data, cap);
	if (!p) {
		b->oom = true; /* old data stays owned by b */
		return false;
	}
	b->data = p;
	b->cap = cap;
	return true;
}

void vt__buf_putn(struct vt_buf *b, const void *p, size_t n) {
	if (!n || !reserve(b, n)) return;
	memcpy(b->data + b->len, p, n);
	b->len += n;
	b->data[b->len] = '\0';
}

void vt__buf_puts(struct vt_buf *b, const char *s) {
	vt__buf_putn(b, s, strlen(s));
}

void vt__buf_putc(struct vt_buf *b, char ch) {
	vt__buf_putn(b, &ch, 1);
}

void vt__buf_escape(struct vt_buf *b, const char *s) {
	static const char hex[] = "0123456789ABCDEF";

	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		unsigned char ch = *p;
		if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') ||
		    (ch >= '0' && ch <= '9') || ch == '-' || ch == '.' ||
		    ch == '_' || ch == '~') {
			vt__buf_putc(b, (char)ch);
		} else {
			char e[3] = {'%', hex[ch >> 4], hex[ch & 15]};
			vt__buf_putn(b, e, sizeof e);
		}
	}
}

void vt__buf_free(struct vt_buf *b) {
	free(b->data);
	*b = (struct vt_buf){.max = b->max};
}
