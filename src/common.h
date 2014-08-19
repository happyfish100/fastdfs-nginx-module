/**
* Copyright (C) 2008 Happy Fish / YuQing
*
* FastDFS may be copied only under the terms of the GNU General
* Public License V3, which may be found in the FastDFS source kit.
* Please visit the FastDFS Home Page http://www.csource.org/ for more detail.
**/

#ifndef FDFS_MOD_COMMON_H
#define FDFS_MOD_COMMON_H

#include <time.h>
#include "tracker_types.h"

#ifndef HTTP_OK
#define HTTP_OK                    200
#endif

#ifndef HTTP_NOCONTENT
#define HTTP_NOCONTENT             204
#endif

#ifndef HTTP_PARTIAL_CONTENT
#define HTTP_PARTIAL_CONTENT       206
#endif

#ifndef HTTP_MOVEPERM
#define HTTP_MOVEPERM              301
#endif

#ifndef HTTP_MOVETEMP
#define HTTP_MOVETEMP              302
#endif

#ifndef HTTP_NOTMODIFIED
#define HTTP_NOTMODIFIED           304
#endif

#ifndef HTTP_BADREQUEST
#define HTTP_BADREQUEST            400
#endif

#ifndef HTTP_NOTFOUND
#define HTTP_NOTFOUND              404
#endif

#ifndef HTTP_INTERNAL_SERVER_ERROR
#define HTTP_INTERNAL_SERVER_ERROR 500
#endif

#ifndef HTTP_SERVUNAVAIL
#define HTTP_SERVUNAVAIL           503
#endif

#ifndef FDFS_STORAGE_STORE_PATH_PREFIX_CHAR
#define FDFS_STORAGE_STORE_PATH_PREFIX_CHAR  'M'
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct fdfs_http_response;

typedef void (*FDFSOutputHeaders)(void *arg, struct fdfs_http_response *pResponse);
typedef int (*FDFSSendReplyChunk)(void *arg, const bool last_buff, \
				const char *buff, const int size);
typedef int (*FDFSSendFile)(void *arg, const char *filename, \
	const int filename_len, const int64_t file_offset, \
	const int64_t download_bytes);

typedef int (*FDFSProxyHandler)(void *arg, const char *dest_ip_addr);

struct fdfs_http_response {
	int status;  //HTTP status
	time_t last_modified;  //last modified time of the file
	int redirect_url_len;
	int range_len;
	int content_range_len;
	int64_t content_length;
	char *content_type;
	char *attachment_filename;
	char redirect_url[256];
	char content_disposition[128];
	char range[64];
	char content_range[64];
	char last_modified_buff[32];
	bool header_outputed;   //if header output
};

struct fdfs_http_range {
	int64_t start;
	int64_t end;
};

struct fdfs_http_context {
	int server_port;
	bool header_only;
	bool if_range;
	struct fdfs_http_range range;
	char if_modified_since[32];
	char *url;
	void *arg; //for callback
	FDFSOutputHeaders output_headers;
	FDFSSendFile send_file;   //nginx send file
	FDFSSendReplyChunk send_reply_chunk;
	FDFSProxyHandler proxy_handler; //nginx proxy handler 
};

struct fdfs_download_callback_args {
	struct fdfs_http_context *pContext;
	struct fdfs_http_response *pResponse;
	int64_t sent_bytes;  //sent bytes
};

/**
* init function
* params:
* return: 0 success, !=0 fail, return the error code
*/
int fdfs_mod_init();

/**
* http request handler
* params:
*	pContext the context
* return: http status code, HTTP_OK success, != HTTP_OK fail
*/
int fdfs_http_request_handler(struct fdfs_http_context *pContext);

/**
* format http datetime
* params:
*	t the time
*       buff the string buffer
*       buff_size the buffer size
* return: 0 success, !=0 fail, return the error code
*/
//int fdfs_format_http_datetime(time_t t, char *buff, const int buff_size);

/**
* parse range parameter
* params:
*	value the range value
*	rang the range object, store start and end position
* return: 0 success, !=0 fail, return the error code
*/
int fdfs_parse_range(const char *value, struct fdfs_http_range *range);

#ifdef __cplusplus
}
#endif

#endif
