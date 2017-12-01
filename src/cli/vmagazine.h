#ifndef CLI_VMAGANIZE_H
#define CLI_VMAGANIZE_H

#include <stdlib.h>
#include <darr.h>

#include "src/magic/magic.h"
#include "src/cli/val.h"

/*
 * A structure that holds cli_vals.
 */
struct vmagazine {
	cli_val template_value;

	void *template_address;

	size_t size;

	struct darr values;
};

/*
 * Result codes.
 */
enum vmagazine_result {
	VMAGAZINE_OK,
	VMAGAZINE_OUT_OF_MEMORY,
	VMAGAZINE_PARSE_FAILURE,
};

/*
 * Initializes the data structure.
 */
inline enum vmagazine_result vmagazine_init(struct vmagazine *this)
{
	this->size = 0;
	this->template_value = cli_val_nil();
	darr_init(&this->values, sizeof(cli_val));

	if (!darr_resize(&this->values, 10)) {
		darr_deinit(&this->values);
		return VMAGAZINE_OUT_OF_MEMORY;
	}

	return VMAGAZINE_OK;
}

/*
 * Deinitializes the data structure.
 */
inline void vmagazine_deinit(struct vmagazine *this)
{
	for (size_t i = 0; i < this->size; ++i) {
		cli_val *e = darr_element(&this->values, i);
		cli_val_destroy(*e);
	}

	darr_deinit(&this->values);

	if (this->template_value != cli_val_nil()) {
		cli_val_destroy(this->template_value);
	}
}

/*
 * Sets the address that will be used and incremented when parsing values.
 */
inline void vmagazine_template_address_set(struct vmagazine *this, void *address)
{
	this->template_address = address;
}

/*
 * Sets the value that will be used to parse values.
 */
inline void vmagazine_template_value_set(struct vmagazine *this, cli_val value)
{
	this->template_value = cli_val_create_clone(value);
}

/*
 * Number of values being hold.
 */
inline size_t vmagazine_size(struct vmagazine *this)
{
	return this->size;
}

/*
 * Returns a pointer to a value.
 *
 * This pointer is invalidated when the number of values changes.
 */
inline cli_val *vmagazine_value(struct vmagazine *this, size_t index)
{
	return darr_element(&this->values, index);
}

/*
 * Parses text values.
 */
inline enum vmagazine_result vmagazine_parse_text(struct vmagazine *this, const char *str, size_t length)
{
	enum vmagazine_result ret = VMAGAZINE_OK;

	size_t index = 0;

	while (index < length) {
		cli_val value = cli_val_create_clone(this->template_value);

		if (value == cli_val_nil()) {
			ret = VMAGAZINE_OUT_OF_MEMORY;
			goto exit0;
		}

		cli_val_address_set(value, this->template_address);

		if (!cli_val_parse_text(value, &str[index])) {
			cli_val_destroy(value);
			ret = VMAGAZINE_PARSE_FAILURE;
			goto exit0;
		}

		this->template_address = (char *) this->template_address + cli_val_sizeof(value);

		cli_val *element = darr_element(&this->values, this->size++);
		*element = value;

		if (this->size >= darr_size(&this->values)) {
			if (!darr_grow(&this->values, darr_size(&this->values))) {
				cli_val_destroy(value);
				ret = VMAGAZINE_OUT_OF_MEMORY;
				goto exit0;
			}
		}

		switch (cli_val_type(value)) {
		case CLI_VAL_TYPE_TEXT:
			index += cli_val_sizeof(value);
			break;

		default:
			index = length;
			break;
		}
	}

exit0:
	return ret;
}

/*
 * Parses binary values.
 *
 * The binary parameter will be read up to the amount passed in size. The read
 * parameter will be written the number of bytes that were read from binary.
 *
 * The read parameter will only be written if the function succeeded.
 */
inline enum vmagazine_result vmagazine_parse_binary(struct vmagazine *this, const unsigned char *binary, size_t size, size_t *read)
{
	enum vmagazine_result ret = VMAGAZINE_OK;

	size_t index = 0;

	while (index < size) {
		cli_val value = cli_val_create_clone(this->template_value);

		if (value == cli_val_nil()) {
			ret = VMAGAZINE_OUT_OF_MEMORY;
			goto exit0;
		}

		cli_val_address_set(value, this->template_address);

		size_t progress = cli_val_parse_binary(value, &binary[index], size - index);

		if (progress == 0) {
			cli_val_destroy(value);
			ret = VMAGAZINE_PARSE_FAILURE;
			goto exit0;
		}

		this->template_address = (char *) this->template_address + cli_val_sizeof(value);

		cli_val *element = darr_element(&this->values, this->size++);
		*element = value;

		if (this->size >= darr_size(&this->values)) {
			if (!darr_grow(&this->values, darr_size(&this->values))) {
				cli_val_destroy(value);
				ret = VMAGAZINE_OUT_OF_MEMORY;
				goto exit0;
			}
		}

		index += progress;
	}

	*read = size - index;
exit0:
	return ret;
}

#endif /* CLI_VMAGAZINE */
