#include <stdio.h>

#include "cli/pattern/pattern.h"
#include "cli/parser/parser.h"

enum pattern_type {
	PATTERN_TYPE_BYTE_VALUE,
	PATTERN_TYPE_ANY_BYTE,
};

struct pattern {
	int type;
};

struct pattern_byte_value {
	struct pattern p;

	char value;
};

struct pattern_any_byte;

struct pattern_list_node {
	struct pattern *pattern;
	struct pattern_list_node *next;
};

struct pattern_list {
	struct pattern_list_node *first;
	struct pattern_list_node *last;
};

struct cli_pattern {
	int error;

	size_t error_compile_offset;

	struct pattern_list patterns;

	struct pattern_list_node *last_pattern;

	int finished;
};

static void cli_pattern_error_set(cli_pattern cp, int error)
{
	cp->error = error;
}

static void destroy_pattern(struct pattern *p)
{
	if (p->type == PATTERN_TYPE_ANY_BYTE) {
		return;
	}

	free(p);
}

static void pattern_list_append_node(struct pattern_list *l, struct pattern_list_node *n)
{
	if (l->first == NULL) {
		l->first = n;
		l->last = n;
	} else {
		l->last->next = n;
		l->last = n;
	}
}

static struct pattern_list_node *create_pattern_list_node(void)
{
	struct pattern_list_node *n = malloc(sizeof(*n));

	n->pattern = NULL;
	n->next = NULL;

	return n;
}

static void destroy_pattern_list_node(struct pattern_list_node *n)
{
	free(n);
}

static void clear_pattern_list(struct pattern_list *l)
{
	if (l->first == NULL) {
		return;
	}

	struct pattern_list_node *c = l->first;
	struct pattern_list_node *n;

	do {
		n = c->next;

		destroy_pattern(c->pattern);
		destroy_pattern_list_node(c);
	} while ((c = n));

	l->first = NULL;
	l->last = NULL;
}

static struct pattern_byte_value *create_pattern_byte_value()
{
	struct pattern_byte_value *p = malloc(sizeof(*p));

	p->p.type = PATTERN_TYPE_BYTE_VALUE;

	return p;
}

static struct pattern_any_byte *create_pattern_any_byte()
{
	static struct pattern p = {
		.type = PATTERN_TYPE_ANY_BYTE,
	};

	return (struct pattern_any_byte *) &p;
}

static int parse_pattern_opt_whitespace(struct cli_pattern *cp, struct pattern_list *l, const char **s)
{
	size_t consumed = cli_parse_skip_chars(*s, " \n\t");

	*s += consumed;

	return 1;
}

static int parse_pattern_whitespace(struct cli_pattern *cp, struct pattern_list *l, const char **s)
{
	const char *orig = *s;

	if (!parse_pattern_opt_whitespace(cp, l, s)) {
		return 0;
	}

	if (orig == *s) {
		return 0;
	}

	return 1;
}

static int parse_pattern_byte_value(struct cli_pattern *cp, struct pattern_list *l, const char **s)
{
	char b;

	if (!cli_parse_is_hex_digit((*s)[0]) || !cli_parse_is_hex_digit((*s)[1])) {
		return 0;
	}

	if (sscanf(*s, "%hhx", &b) != 1) {
		return 0;
	}

	struct pattern_list_node *n = create_pattern_list_node();

	struct pattern_byte_value *p = create_pattern_byte_value();
	p->value = b;

	n->pattern = (struct pattern *) p;

	pattern_list_append_node(l, n);

	*s += 2;

	return 1;
}

static int parse_pattern_any_byte(struct cli_pattern *cp, struct pattern_list *l, const char **s)
{
	if ((*s)[0] != '?' || (*s)[1] != '?') {
		return 0;
	}

	struct pattern_list_node *n = create_pattern_list_node();

	struct pattern_any_byte *p = create_pattern_any_byte();

	n->pattern = (struct pattern *) p;

	pattern_list_append_node(l, n);

	*s += 2;

	return 1;
}

static int parse_pattern(struct cli_pattern *cp, struct pattern_list *l, const char *s)
{
	const char *orig = s;
	cp->error_compile_offset = 0;

	if (!parse_pattern_opt_whitespace(cp, l, &s)) {
		return 0;
	}

	if (*s == '\0') {
		cli_pattern_error_set(cp, CLI_PATTERN_ERROR_EMPTY_PATTERN);
		return 0;
	}

	while (*s != '\0') {
		if (parse_pattern_byte_value(cp, l, &s)) {
			if (*s != '\0' && !parse_pattern_whitespace(cp, l, &s)) {
				cli_pattern_error_set(cp, CLI_PATTERN_ERROR_MISSING_WHITESPACE);
				cp->error_compile_offset = s - orig;
				return 0;
			}
			continue;
		}

		if (parse_pattern_any_byte(cp, l, &s)) {
			if (*s != '\0' && !parse_pattern_whitespace(cp, l, &s)) {
				cli_pattern_error_set(cp, CLI_PATTERN_ERROR_MISSING_WHITESPACE);
				cp->error_compile_offset = s - orig;
				return 0;
			}
			continue;
		}

		cli_pattern_error_set(cp, CLI_PATTERN_ERROR_INVALID_PATTERN);
		cp->error_compile_offset = s - orig;
		return 0;
	}

	return 1;
}

cli_pattern cli_pattern_create(void)
{
	struct cli_pattern *cp = malloc(sizeof(*cp));

	if (cp == NULL) {
		return NULL;
	}

	cp->error = 0;
	cp->patterns.first = NULL;
	cp->patterns.last = NULL;
	cp->last_pattern = NULL;
	cp->finished = 0;

	return cp;
}

void cli_pattern_destroy(cli_pattern cp)
{
	clear_pattern_list(&cp->patterns);
	free(cp);
}

int cli_pattern_compile(cli_pattern cp, const char *s)
{
	clear_pattern_list(&cp->patterns);

	if (!parse_pattern(cp, &cp->patterns, s)) {
		clear_pattern_list(&cp->patterns);
	}

	return 1;
}

int cli_pattern_ready(cli_pattern cp)
{
	return cp->patterns.first != NULL;
}

void cli_pattern_new(cli_pattern cp)
{
	cp->last_pattern = NULL;
	cp->finished = 0;
}

int cli_pattern_input(cli_pattern cp, const char* data, size_t size)
{
	if (!cli_pattern_ready(cp)) {
		cli_pattern_error_set(cp, CLI_PATTERN_ERROR_COMPILE_PATTERN);
		return 0;
	}

	if (cli_pattern_finished(cp)) {
		// Nothing to do anymore.
		return 0;
	}

	struct pattern_list_node *n;

	if (cp->last_pattern) {
		n = cp->last_pattern->next;
	} else {
		n = cp->patterns.first;
	}

	size_t read = 0;

	for (size_t i = 0; i < size; ++i) {
		switch (n->pattern->type)  {
		case PATTERN_TYPE_BYTE_VALUE: {
			struct pattern_byte_value *p = (struct pattern_byte_value *) n->pattern;

			if (p->value != data[i]) {
				cp->finished = 1;
				return read;
			}
			break;
		}

		case PATTERN_TYPE_ANY_BYTE:
			// Always passes.
			break;
		}

		++read;

		cp->last_pattern = n;

		if (cp->last_pattern == cp->patterns.last) {
			cp->finished = 1;
			break;
		}

		n = n->next;
	}

	return read;
}

int cli_pattern_finished(cli_pattern cp)
{
	return cp->finished;
}

int cli_pattern_matched(cli_pattern cp)
{
	return cp->finished && cp->patterns.last == cp->last_pattern;
}

int cli_pattern_error(cli_pattern cp)
{
	if (cp == NULL) {
		return CLI_PATTERN_ERROR_OUT_OF_MEMORY;
	}

	return cp->error;
}

int cli_pattern_error_compile_offset(cli_pattern cp)
{
	return cp->error_compile_offset;
}
