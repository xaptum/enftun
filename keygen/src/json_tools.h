//
// Created by dan on 5/8/20.
//

#ifndef ENFTUN_JSON_TOOLS_H
#define ENFTUN_JSON_TOOLS_H

size_t copy_json_str(char *dst, json_t *j_str, size_t dst_len);
char *new_json_str(json_t *j_str);

#endif //ENFTUN_JSON_TOOLS_H
