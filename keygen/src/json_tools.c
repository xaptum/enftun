#include <jansson.h>
#include <string.h>

/**
 * ep_new_json_str() - Copies a JSON string to an existing buffer
 * @dst: The buffer to copy into
 * @j_Str: The json string to copy
 * @len: The length of the buffer being copied into
 *
 * Copies the json string into the @dst. If @j_str is too large the copy will be truncated.
 *
 * Return: 0 on success or the number of bytes truncated.
 */
size_t copy_json_str(char *dst, json_t *j_str, size_t dst_len)
{
    const char *src = json_string_value(j_str);
    size_t src_len = strlen(src);
    size_t copy_len = (dst_len<=src_len) ? dst_len : src_len;
    memcpy(dst, src, copy_len);
    dst[copy_len] = '\0';
    return src_len-copy_len;
}

/**
 * ep_new_json_str() - Allocate a new string based on a json string
 * @j_str: The JSON string to copy
 *
 * Caller must free returned buffer.
 *
 * Return: A newly allocated buffer with the json string copied inside or NULL if j_str is not a string type
 */
char *new_json_str(json_t *j_str)
{
    const char *src = json_string_value(j_str);
    char *dst = NULL;
    if (src) {
        dst = malloc(strlen(src) + 1);
        strcpy(dst, src);
    }
    return dst;
}
