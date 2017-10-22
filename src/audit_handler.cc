/*
 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

/*
 * audit_handler.cc
 *
 *  Created on: Feb 6, 2011
 *      Author: guyl
 */

#include "audit_handler.h"
// for definition of sockaddr_un
#include <sys/un.h>
#include <stdio_ext.h>
#include <limits.h>
#include <unistd.h>
#include "static_assert.h"

#if MYSQL_VERSION_ID < 50600
// for 5.5 and 5.1
extern "C" void vio_timeout(Vio *vio,uint which, uint timeout);
#endif

// utility macro to log also with a date as a prefix
// FIXME: This is no longer used. Remove?
#define log_with_date(f, ...) do {\
    struct tm tm_tmp;\
    time_t result = time(NULL);\
    localtime_r(&result, &tm_tmp);\
    fprintf(f, "%02d%02d%02d %2d:%02d:%02d: ",\
                    tm_tmp.tm_year % 100,\
                    tm_tmp.tm_mon+1,\
                    tm_tmp.tm_mday,\
                    tm_tmp.tm_hour,\
                    tm_tmp.tm_min,\
                    tm_tmp.tm_sec);\
    fprintf(f, __VA_ARGS__);\
} while (0)


// initialize static stuff
ThdOffsets Audit_formatter::thd_offsets = { 0 };
Audit_handler *Audit_handler::m_audit_handler_list[Audit_handler::MAX_AUDIT_HANDLERS_NUM];

#if MYSQL_VERSION_ID < 50709
#define C_STRING_WITH_LEN(X) ((char *) (X)), ((size_t) (sizeof(X) - 1))
#endif

//////////////////////////////////////////////
// Yajl alloc funcs based upon thd_alloc
static void * yajl_thd_malloc(void *ctx, size_t sz)
{
	THD *thd = (THD*) ctx;
	// we allocate plus sizeof(size_t) and stored the alloced size
	// at the start of the pointer (for support of realloc)
	size_t *ptr = (size_t *) thd_alloc(thd, sz + sizeof(size_t));
	if (ptr) 
	{
		*ptr = sz; //set the size at the start of the memory
		ptr++;
	}
	return ptr;
}

static void * yajl_thd_realloc(void *ctx, void * previous,
		size_t sz)
{
	THD *thd = (THD*)ctx;
	void *ptr;
	if ((ptr = yajl_thd_malloc(thd,sz)))
	{
		if (previous)
		{
			// copy only the previous allocated size (which is
			// stored just before the pointer passed in)
			size_t prev_sz = *(((size_t *)previous) - 1);			
			memcpy(ptr,previous, prev_sz);
		}
	}
	return ptr;
}

static void yajl_thd_free(void *ctx, void * ptr)
{
	//do nothing as thd_alloc deosn't require free
	return;
}

static void yajl_set_thd_alloc_funcs(THD * thd, yajl_alloc_funcs * yaf)
{
	yaf->malloc = yajl_thd_malloc;
	yaf->free = yajl_thd_free;
	yaf->realloc = yajl_thd_realloc;
	yaf->ctx = thd;
}

//////////////////////////////////////////////

const char *Audit_formatter::retrieve_object_type(TABLE_LIST *pObj)
{
	if (table_is_view(pObj))
	{
		return "VIEW";
	}
	return "TABLE";
}

// This routine used to pull the client port out of the thd->net->vio->remote
// object, but on MySQL 5.7 the port is zero.  So we resort to getting the
// underlying fd and using getpeername(2) on it.

int Audit_formatter::thd_client_port(THD *thd)
{
	int port = -1;
	int sock = thd_client_fd(thd);

	if (sock < 0)
	{
		return port;	// shouldn't happen
	}

	struct sockaddr_storage addr;
	socklen_t len = sizeof(addr);

	// get port of the guy on the other end of our connection
	if (getpeername(sock, (struct sockaddr *) & addr, & len) < 0)
	{
		return port;
	}


	if (addr.ss_family == AF_INET)
	{
		struct sockaddr_in *sin = (struct sockaddr_in *) & addr;
		port = ntohs(sin->sin_port);
	}
	else
	{
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *) & addr;
		port = ntohs(sin->sin6_port);
	}

	if (port == 0)	// shouldn't happen
	{
		port = -1;
	}

	return port;
}

void Audit_handler::stop_all()
{
	for (size_t i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
	{
		if (m_audit_handler_list[i] != NULL)
		{
			m_audit_handler_list[i]->set_enable(false);
		}
	}
}

void Audit_handler::log_audit_all(ThdSesData *pThdData)
{
	for (size_t i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
	{
		if (m_audit_handler_list[i] != NULL)
		{
			m_audit_handler_list[i]->log_audit(pThdData);
		}
	}
}

void Audit_handler::set_enable(bool val)
{
	lock_exclusive();
	if (m_enabled == val) // we are already enabled simply return
	{
		unlock();
		return;
	}
	m_enabled = val;
	if (m_enabled)
	{
		// call the startup of the handler
		handler_start();
	}
	else
	{
		// call the cleanup of the handler
		handler_stop();
	}
	unlock();
}

void Audit_handler::flush()
{
	lock_exclusive();
	if (! m_enabled) // if not running we don't flush
	{
		unlock();
		return;
	}
	// call the cleanup of the handler
	handler_stop();
	// call the startup of the handler
	handler_start();
	sql_print_information("%s Log flush complete.", AUDIT_LOG_PREFIX);
	unlock();
}

void Audit_handler::log_audit(ThdSesData *pThdData)
{
	lock_shared();
	if (! m_enabled)
	{
		unlock();
		return;
	}
	// sanity check that offsets match
	// we can also consider using security context function to do some sanity checks
	//  char buffer[2048];
	//  thd_security_context(thd, buffer, 2048, 2000);
	//  fprintf(log_file, "info from security context: %s\n", buffer);
	unsigned long inst_thread_id = Audit_formatter::thd_inst_thread_id(pThdData->getTHD());
	unsigned long plug_thread_id = thd_get_thread_id(pThdData->getTHD());
	if (inst_thread_id != plug_thread_id)
	{
		if (m_print_offset_err)
		{
			m_print_offset_err = false;
			sql_print_error(
					"%s Thread id from thd_get_thread_id doesn't match calculated value from offset %lu <> %lu. Aborting!",
					AUDIT_LOG_PREFIX, inst_thread_id, plug_thread_id);
		}
	}
	else
	{
		// offsets are good
		m_print_offset_err = true; // mark to print offset err to log in case we encounter in the future		
		// check if failed
		bool do_log = true;
		if (m_failed)
		{
			do_log = false;
			bool retry = m_retry_interval > 0 &&
				difftime(time(NULL), m_last_retry_sec_ts) > m_retry_interval;
			if (retry)
			{
				pthread_mutex_lock(&LOCK_io);
				//get the io lock. After acquiring the lock do another check that we really need to start (maybe another thread did this already)
				if (!m_failed)
				{
					do_log = true;
				}
				else if (m_retry_interval > 0 &&
					difftime(time(NULL), m_last_retry_sec_ts) > m_retry_interval)
				{
					do_log = handler_start_nolock();
				}
				pthread_mutex_unlock(&LOCK_io);
				
			}
		}
		if (do_log)
		{
			if (! handler_log_audit(pThdData))
			{
				//failure - acquire io lock to set failed and do stop
				pthread_mutex_lock(&LOCK_io);
				if(!m_failed) //make sure someone else didn't set this already 
				{
					set_failed();
					handler_stop_internal();
				}
				pthread_mutex_unlock(&LOCK_io);
			}
		}		
	}
	unlock();
}

void Audit_file_handler::close()
{
	if (m_log_file)
	{
		my_fclose(m_log_file, MYF(0));
	}
	m_log_file = NULL;
}

ssize_t Audit_file_handler::write_no_lock(const char *data, size_t size)
{	
	ssize_t res = -1;
	if(m_log_file)
	{
		res = my_fwrite(m_log_file, (uchar *) data, size, MYF(0));
		if (res && m_sync_period && ++m_sync_counter >= m_sync_period)
		{
			m_sync_counter = 0;
			// Note fflush() only flushes the user space buffers provided by the C library.
			// To ensure that the data is physically stored on disk the kernel buffers must be flushed too,
			// e.g. with sync(2) or fsync(2).
			res = (fflush(m_log_file) == 0);
			if (res)
			{
				int fd = fileno(m_log_file);
				res = (my_sync(fd, MYF(MY_WME)) == 0);
			}
		}
		if (res < 0) // log the error
		{
			sql_print_error("%s failed writing to file: %s. Err: %s",
					AUDIT_LOG_PREFIX, m_io_dest, strerror(errno));
		}		
	}
	return res;
}

int Audit_file_handler::open(const char *io_dest, bool log_errors)
{
	char format_name[FN_REFLEN];

	fn_format(format_name, io_dest, "", "", MY_UNPACK_FILENAME);
	m_log_file = my_fopen(format_name,  O_WRONLY | O_APPEND| O_CREAT, MYF(0));
	if (! m_log_file)
	{
		if (log_errors)
		{
			sql_print_error(
					"%s unable to open file %s: %s. audit file handler disabled!!",
					AUDIT_LOG_PREFIX, m_io_dest, strerror(errno));
		}
		return -1;
	}

	ssize_t bufsize = BUFSIZ;
	int res = 0;
	// 0 -> use default, 1 or negative -> disabled
	if (m_bufsize > 1)
	{
		bufsize = m_bufsize;
	}

	if (1 == m_bufsize || m_bufsize < 0)
	{
		// disabled
		res = setvbuf(m_log_file, NULL,  _IONBF, 0);
	}
	else
	{
		res = setvbuf(m_log_file, NULL, _IOFBF, bufsize);

	}

	if (res)
	{
		sql_print_error(
				"%s unable to set bufsize [%zd (%ld)] for file %s: %s.",
				AUDIT_LOG_PREFIX, bufsize, m_bufsize, m_io_dest, strerror(errno));
	}
	sql_print_information("%s bufsize for file [%s]: %zd. Value of json_file_bufsize: %ld.", AUDIT_LOG_PREFIX, m_io_dest,
			__fbufsize(m_log_file), m_bufsize);
	return 0;
}

// no locks. called by handler_start and when it is time to retry
bool Audit_io_handler::handler_start_internal()
{
	if (! m_io_dest || strlen(m_io_dest) == 0)
	{
		if (m_log_io_errors)
		{
			sql_print_error(
					"%s %s: io destination not set. Not connecting.",
					AUDIT_LOG_PREFIX,  m_io_type);
		}
		return false;
	}
	if (open(m_io_dest, m_log_io_errors) != 0)
	{
		// open failed
		return false;
	}
	ssize_t res = m_formatter->start_msg_format(this);
	/*
	 * Sanity check of writing to the log. If we fail, we print an
	 * error and disable this handler.
	 */
	if (res < 0)
	{
		if (m_log_io_errors)
		{
			sql_print_error(
					"%s unable to write header msg to %s: %s.",
					AUDIT_LOG_PREFIX, m_io_dest, strerror(errno));
		}
		close();
		return false;
	}
	sql_print_information("%s success opening %s: %s.", AUDIT_LOG_PREFIX, m_io_type, m_io_dest);
	return true;
}

bool Audit_io_handler::handler_log_audit(ThdSesData *pThdData)
{
	return (m_formatter->event_format(pThdData, this) >= 0);
}

void Audit_io_handler::handler_stop_internal()
{
	if (! m_failed)
	{
		m_formatter->stop_msg_format(this);
	}
	close();
}

bool Audit_handler::handler_start_nolock()
{
	bool res = handler_start_internal();
	if (res)
	{
		m_failed = false;
	}
	else
	{
		set_failed();
		handler_stop_internal();
	}
	return res;
}

void Audit_handler::handler_start()
{
	pthread_mutex_lock(&LOCK_io);
	m_log_io_errors = true;
	handler_start_nolock();
	pthread_mutex_unlock(&LOCK_io);
}

void Audit_handler::handler_stop()
{
	pthread_mutex_lock(&LOCK_io);
	handler_stop_internal();
	pthread_mutex_unlock(&LOCK_io);
}

/////////////////// Audit_socket_handler //////////////////////////////////

void Audit_socket_handler::close()
{
	if (m_vio)
	{
		// no need for vio_close as is called by delete (additionally close changed its name to vio_shutdown in 5.6.11)
		vio_delete((Vio*)m_vio);
	}
	m_vio = NULL;
}

ssize_t Audit_socket_handler::write_no_lock(const char *data, size_t size)
{	
	ssize_t res = -1;
	if (m_vio)
	{
		res = vio_write((Vio*)m_vio, (const uchar *) data, size);
		if (res < 0) // log the error
		{
			sql_print_error("%s failed writing to socket: %s. Err: %s",
					AUDIT_LOG_PREFIX, m_io_dest, strerror(vio_errno((Vio*)m_vio)));
		}
	}
	return res;
}

int Audit_socket_handler::open(const char *io_dest, bool log_errors)
{
	// open the socket
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0)
	{
		if (log_errors)
		{
			sql_print_error(
					"%s unable to create unix socket: %s.",
					AUDIT_LOG_PREFIX, strerror(errno));
		}
		return -1;
	}

	// connect the socket
	m_vio = vio_new(sock, VIO_TYPE_SOCKET, VIO_LOCALHOST);
	struct sockaddr_un UNIXaddr;
	UNIXaddr.sun_family = AF_UNIX;
	strmake(UNIXaddr.sun_path, io_dest, sizeof(UNIXaddr.sun_path)-1);
#if MYSQL_VERSION_ID < 50600
	if (my_connect(sock,(struct sockaddr *) &UNIXaddr, sizeof(UNIXaddr),
				m_connect_timeout))
#else
	// in 5.6 timeout is in ms
	if (vio_socket_connect((Vio*)m_vio,(struct sockaddr *) &UNIXaddr, sizeof(UNIXaddr),
				m_connect_timeout * 1000))
#endif
	{
		if (log_errors)
		{
			sql_print_warning(
				"%s unable to connect to socket: %s. err: %s.",
				AUDIT_LOG_PREFIX, m_io_dest, strerror(errno));

			// The next time this occurs, log as an error
			m_log_with_error_severity = true;
		}
		// Only if issue persist also in second retry, report it by using 'error' severity.
		else if (m_log_with_error_severity)
		{
			sql_print_error(
				"%s unable to connect to socket: %s. err: %s.",
				AUDIT_LOG_PREFIX, m_io_dest, strerror(errno));

			m_log_with_error_severity = false;
		}

		close();
		return -2;
	}

	// At this point, connected successfully.
	// Ensure same behavior in case first time failed but second retry was successful
	m_log_with_error_severity = false;

	if (m_write_timeout > 0)
	{
		int timeout = m_write_timeout / 1000;	// milliseconds to seconds, integer dvision
		if (timeout == 0)
		{
			timeout = 1;	// round up to 1 second
		}
		// we don't check the result of this call since in earlier
		// versions it returns void
		//
		// 1 as the 2nd argument means write timeout
		vio_timeout((Vio*)m_vio, 1, timeout);
	}

	return 0;
}

//////////////////////// Audit Socket handler end ///////////////////////////////////////////



static yajl_gen_status yajl_add_string(yajl_gen hand, const char *str)
{
	return yajl_gen_string(hand, (const unsigned char *) str, strlen(str));
}

static void yajl_add_string_val(yajl_gen hand, const char *name, const char *val)
{
	if (0 == val)
	{
		return; // we don't add NULL values to json
	}
	yajl_add_string(hand, name);
	yajl_add_string(hand, val);
}

static void yajl_add_string_val(yajl_gen hand, const char *name, const char *val, size_t val_len)
{
	yajl_add_string(hand, name);
	yajl_gen_string(hand, (const unsigned char*)val, val_len);
}

static void yajl_add_uint64(yajl_gen gen, const char *name, uint64 num)
{
	const size_t max_int64_str_len = 21;
	char buf[max_int64_str_len];
	snprintf(buf, max_int64_str_len, "%llu", num);
	yajl_add_string_val(gen, name, buf);
}

static void yajl_add_obj(yajl_gen gen, const char *db, const char *ptype, const char *name = NULL)
{
	if (db)
	{
		yajl_add_string_val(gen, "db", db);
	}
	if (name)
	{
		yajl_add_string_val(gen, "name", name);
	}
	yajl_add_string_val(gen, "obj_type", ptype);
}

static const char *retrieve_user(THD *thd)
{
	const char *user = Audit_formatter::thd_inst_main_security_ctx_user(thd);
	if (user != NULL && *user != '\0') // non empty
	{
		return user;
	}
	user = Audit_formatter::thd_inst_main_security_ctx_priv_user(thd); // try using priv user
	if (user != NULL && *user != '\0') // non empty
	{
		return user;
	}
	return ""; // always use at least the empty string
}


// will return a pointer to the query and set len with the length of the query
// starting with MySQL version 5.1.41 thd_query_string is added
// And at 5.7 it changed
#if ! defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 50709

extern "C" LEX_CSTRING thd_query_unsafe(MYSQL_THD thd);

static const char *thd_query_str(THD *thd, size_t *len)
{
	const LEX_CSTRING str = thd_query_unsafe(thd);
	if (str.length > 0)
	{
		*len = str.length;
		return str.str;
	}
	*len = 0;
	return NULL;
}

#elif defined(MARIADB_BASE_VERSION) || MYSQL_VERSION_ID > 50140

extern "C" {
	MYSQL_LEX_STRING *thd_query_string(MYSQL_THD thd);
}

static const char *thd_query_str(THD *thd, size_t *len)
{
	MYSQL_LEX_STRING *str = thd_query_string(thd);
	if (str)
	{
		*len = str->length;
		return str->str;
	}
	*len = 0;
	return NULL;
}
#else
// we are being compiled against mysql version 5.1.40 or lower (our default compilation env)
// we still want to support thd_query_string if we are run on a version higher than 5.1.40, so we try to lookup the symbol
static LEX_STRING * (*thd_query_string_func)(THD *thd) = (LEX_STRING*(*)(THD*))dlsym(RTLD_DEFAULT, "thd_query_string");
static bool print_thd_query_string_func = true; // debug info print only once

static const char *thd_query_str(THD *thd, size_t *len)
{
	if (print_thd_query_string_func)
	{
		sql_print_information("%s thd_query_string_func: 0x%lx", AUDIT_LOG_PREFIX, (unsigned long)thd_query_string_func);
		print_thd_query_string_func = false;
	}
	if (thd_query_string_func)
	{
		MYSQL_LEX_STRING *str = thd_query_string_func(thd);
		if (str)
		{
			*len = str->length;
			return str->str;
		}
		*len = 0;
		return NULL;
	}
	*len = thd->query_length;
	return thd->query;
}
#endif

ssize_t Audit_json_formatter::start_msg_format(IWriter *writer)
{
	if (! m_write_start_msg) // disabled
	{
		return 0;
	}

	// initialize yajl
	yajl_gen gen = yajl_gen_alloc(NULL);
	yajl_gen_map_open(gen);
	yajl_add_string_val(gen, "msg-type", "header");
	uint64 ts = my_getsystime() / (10000);
	yajl_add_uint64(gen, "date", ts);
	yajl_add_string_val(gen, "audit-version", MYSQL_AUDIT_PLUGIN_VERSION "-" MYSQL_AUDIT_PLUGIN_REVISION);
	yajl_add_string_val(gen, "audit-protocol-version", AUDIT_PROTOCOL_VERSION);
	yajl_add_string_val(gen, "hostname", glob_hostname);
	yajl_add_string_val(gen, "mysql-version", server_version);
	yajl_add_string_val(gen, "mysql-program", my_progname);
	yajl_add_string_val(gen, "mysql-socket", mysqld_unix_port);
	yajl_add_uint64(gen, "mysql-port", mysqld_port);
	yajl_add_uint64(gen, "server_pid", getpid());
	ssize_t res = -2;

	yajl_gen_status stat = yajl_gen_map_close(gen); // close the object
	if (stat == yajl_gen_status_ok) // all is good write the buffer out
	{
		//will add the delimiter to the buffer
		yajl_gen_reset(gen, "\n");
		const unsigned char *text = NULL;
		size_t len = 0;
		yajl_gen_get_buf(gen, &text, &len);
		// no need for lock as it was acquired before as part of the connect
		res = writer->write_no_lock((const char *)text, len);		
	}
	yajl_gen_free(gen); // free the generator
	return res;
}

// This routine replaces clear text with the string in `replace', leaving the rest of the string intact.
//
// thd			- MySQL thread, used for allocating memory
// str			- pointer to start of original string
// str_len		- length thereof
// cleartext_start	- start of cleartext to replace
// cleartext_len	- length of cleartext
// replace		- \0 terminated string with replacement text
static const char *replace_in_string(THD *thd,
					const char *str, size_t str_len,
					size_t cleartext_start, size_t cleartext_len,
					const char *replace)
{
	size_t to_alloc = str_len + strlen(replace) + 1;
	char *new_str = (char *) thd_alloc(thd, to_alloc);
	memset(new_str, '\0', to_alloc);

	// point to text after clear text
	const char *trailing = str + cleartext_start + cleartext_len;
	// how much text after clear text to copy in
	size_t final_to_move = ((str + str_len) - trailing);

	char *pos = new_str;
	memcpy(pos, str, cleartext_start);	// copy front of string
	pos += cleartext_start;

	memcpy(pos, replace, strlen(replace));	// copy replacement text
	pos += strlen(replace);

	memcpy(pos, trailing, final_to_move);	// copy trailing part of string

	return new_str;
}

#ifdef HAVE_SESS_CONNECT_ATTRS
#include <storage/perfschema/pfs_instr.h>

//declare the function: parse_length_encoded_string from: storage/perfschema/table_session_connect.cc
bool parse_length_encoded_string(const char **ptr,
	char *dest, uint dest_size,
	uint *copied_len,
	const char *start_ptr, uint input_length,
	bool copy_data,
	const CHARSET_INFO *from_cs,
	uint nchars_max);

/**
 * Code based upon read_nth_attribute of storage/perfschema/table_session_connect.cc
 * Only difference we do once loop and write out the attributes
 */ 
static void log_session_connect_attrs(yajl_gen gen, THD *thd)
{
	PFS_thread * pfs = PFS_thread::get_current_thread();
	const char * connect_attrs = Audit_formatter::pfs_connect_attrs(pfs);
	const uint connect_attrs_length = Audit_formatter::pfs_connect_attrs_length(pfs);
	const CHARSET_INFO *connect_attrs_cs = Audit_formatter::pfs_connect_attrs_cs(pfs);  

	//sanity max attributes
	const uint max_idx = 32;
	uint idx;
	const char *ptr;  
	bool array_start = false;
	if(!connect_attrs || !connect_attrs_length || !connect_attrs_cs)
	{
		//either offsets are wrong or not set
		return;
	}
	for (ptr= connect_attrs, idx= 0;
			(uint)(ptr - connect_attrs) < connect_attrs_length && idx <= max_idx;
			idx++)
	{
		const uint MAX_COPY_CHARS_NAME = 32;
		const uint MAX_COPY_CHARS_VAL = 256;
		//time 6 (max udf8 char length)
		char attr_name[MAX_COPY_CHARS_NAME*6];
		char attr_value[MAX_COPY_CHARS_VAL *6];
		uint copy_length, attr_name_length, attr_value_length;
		/* always do copying */
		bool fill_in_attr_name= true;
		bool fill_in_attr_value= true;

		/* read the key */
		copy_length = 0;
		if (parse_length_encoded_string(&ptr,
					attr_name, array_elements(attr_name), &copy_length,
					connect_attrs,
					connect_attrs_length,
					fill_in_attr_name,
					connect_attrs_cs, MAX_COPY_CHARS_NAME) || !copy_length)
		{
			//something went wrong or we are done
			break;
		}

		attr_name_length = copy_length;                
		/* read the value */
		copy_length = 0;
		if (parse_length_encoded_string(&ptr,
					attr_value, array_elements(attr_value), &copy_length,
					connect_attrs,
					connect_attrs_length,
					fill_in_attr_value,
					connect_attrs_cs, MAX_COPY_CHARS_VAL) || !copy_length)
		{
			break;
		}          
		attr_value_length= copy_length;
		if(!array_start)
		{
			yajl_add_string(gen, "connect_attrs");
			yajl_gen_map_open(gen);
			array_start = true;
		}
		yajl_gen_string(gen, (const unsigned char*)attr_name, attr_name_length);
		yajl_gen_string(gen, (const unsigned char*)attr_value, attr_value_length);

	} //close for loop
	if(array_start)
	{
		yajl_gen_map_close(gen);
	}
	return;
}
#endif

ssize_t Audit_json_formatter::event_format(ThdSesData *pThdData, IWriter *writer)
{
	THD *thd = pThdData->getTHD();
	unsigned long thdid = thd_get_thread_id(thd);
	query_id_t qid = thd_inst_query_id(thd);

	// initialize yajl
	yajl_alloc_funcs alloc_funcs;
	yajl_set_thd_alloc_funcs(thd, &alloc_funcs);
	yajl_gen gen = yajl_gen_alloc(&alloc_funcs);
	yajl_gen_map_open(gen);
	yajl_add_string_val(gen, "msg-type", "activity");
	// TODO: get the start date from THD (but it is not in millis. Need to think about how we handle this)
	// for now simply use the current time.
	// my_getsystime() time since epoc in 100 nanosec units. Need to devide by 1000*(1000/100) to reach millis
	uint64 ts = my_getsystime() / (10000);
	yajl_add_uint64(gen, "date", ts);
	yajl_add_uint64(gen, "thread-id", thdid);
	yajl_add_uint64(gen, "query-id", qid);
	yajl_add_string_val(gen, "user", pThdData->getUserName());
	yajl_add_string_val(gen, "priv_user", Audit_formatter::thd_inst_main_security_ctx_priv_user(thd));
	yajl_add_string_val(gen, "ip", Audit_formatter::thd_inst_main_security_ctx_ip(thd));

	// For backwards compatibility, we always send "host".
	// If there is no value, send the IP address
	const char *host = Audit_formatter::thd_inst_main_security_ctx_host(thd);
	if (host == NULL || *host == '\0')
	{
		host = Audit_formatter::thd_inst_main_security_ctx_ip(thd);
	}
	yajl_add_string_val(gen, "host", host);

	if (m_write_client_capabilities)
	{
		ulong caps = Audit_formatter::thd_client_capabilities(thd);
		if (caps)
		{
			yajl_add_uint64(gen, "capabilities", caps);
		}
	}

#ifdef HAVE_SESS_CONNECT_ATTRS
	if (m_write_sess_connect_attrs)
	{
		log_session_connect_attrs(gen, thd);
	}
#endif

	if (pThdData->getPeerPid() != 0)	// Unix Domain Socket
	{
		if (m_write_socket_creds)
		{
			yajl_add_uint64(gen, "pid", pThdData->getPeerPid());
			if (pThdData->getOsUser() != NULL)
			{
				yajl_add_string_val(gen, "os_user", pThdData->getOsUser());
			}
			if (pThdData->getAppName() != NULL)
			{
				yajl_add_string_val(gen, "appname", pThdData->getAppName());
			}
		}
	}
	else if (pThdData->getPort() > 0)		// TCP socket
	{
		yajl_add_uint64(gen, "client_port", pThdData->getPort());
	}

	const char *cmd = pThdData->getCmdName();
	ulonglong rows = 0;

	if (pThdData->getStatementSource() == ThdSesData::SOURCE_QUERY_CACHE)
	{
		// from the query cache
		rows = thd_found_rows(thd);
	}
	else if (strcasestr(cmd, "insert") != NULL ||
		 strcasestr(cmd, "update") != NULL ||
		 strcasestr(cmd, "delete") != NULL ||
	         (strcasestr(cmd, "select") != NULL && thd_row_count_func(thd) > 0))
	{
		// m_row_count_func will be -1 for most selects but can be > 0, e.g. select into file
		// thd_row_count_func() returns signed valiue. Don't assign it to rows directly.
		longlong row_count = thd_row_count_func(thd);
		if (row_count > 0)
		{
			rows = row_count;
		}
	}
	else
	{
		rows = thd_sent_row_count(thd);
	}

	if (rows != 0UL)
	{
		yajl_add_uint64(gen, "rows", rows);
	}

	uint code;
	if (pThdData->getErrorCode(code))
	{
		yajl_add_uint64(gen, "status", code); // 0 - success, otherwise reports specific errno
	}

	yajl_add_string_val(gen, "cmd", cmd);

	// get objects
	if (pThdData->startGetObjects())
	{
		yajl_add_string(gen, "objects");
		yajl_gen_array_open(gen);
		const char *db_name = NULL;
		const char *obj_name = NULL;
		const char *obj_type = NULL;
		while (pThdData->getNextObject(&db_name, &obj_name, &obj_type))
		{
			yajl_gen_map_open(gen);
			yajl_add_obj (gen, db_name, obj_type, obj_name );
			yajl_gen_map_close(gen);
		}
		yajl_gen_array_close(gen);
	}

	size_t qlen = 0;
	const char *query = thd_query_str(pThdData->getTHD(), &qlen);
	if (query && qlen > 0)
	{
#if MYSQL_VERSION_ID < 50600
		CHARSET_INFO *col_connection;
#else
		const CHARSET_INFO *col_connection;
#endif
		col_connection = Item::default_charset();

		// See comment below as to why we don't use String class directly, or call
		// pThdData->getTHD()->convert_string (&sQuery,col_connection,&my_charset_utf8_general_ci);
		const char *query_text = query;
		size_t query_len = qlen;

		if (strcmp(col_connection->csname, "utf8") != 0)
		{
			// max UTF-8 bytes per char is 4.
			size_t to_amount = (qlen * 4) + 1;
			char* to = (char *) thd_alloc(thd, to_amount);

			uint errors = 0;

			size_t len = copy_and_convert(to, to_amount,
					&my_charset_utf8_general_ci,
					query, qlen,
					col_connection, & errors);

			to[len] = '\0';

			query = to;
			qlen = len;
		}

		if (m_perform_password_masking
			&& m_password_mask_regex_compiled
			&& m_password_mask_regex_preg
			&& m_perform_password_masking(cmd))
		{
			// do password masking
			int matches[90] = { 0 };
			if (pcre_exec(m_password_mask_regex_preg, NULL, query_text, query_len, 0, 0, matches, array_elements(matches)) >= 0)
			{
				// search for the first substring that matches with the name psw
				char *first = NULL, *last = NULL;
				int entrysize = pcre_get_stringtable_entries(m_password_mask_regex_preg, "psw", &first, &last);
				if (entrysize > 0)
				{
					for (unsigned char *entry = (unsigned char *)first; entry <= (unsigned char *)last; entry += entrysize)
					{
						// first 2 bytes give us the number
						int n = (((int)(entry)[0]) << 8) | (entry)[1];
						if (n > 0 && n < (int)array_elements(matches) && matches[n*2] >= 0)
						{
							// We have a match.

							// Starting with MySQL 5.7, we cannot use the String::replace() function.
							// Doing so causes a crash in the string's destructor. It appears that the
							// interfaces in MySQL have changed fairly drastically. So we just do the
							// replacement ourselves.
							const char *pass_replace = "***";
							const char *updated = replace_in_string(thd,
											query_text,
											query_len,
											matches[n*2],
											matches[(n*2) + 1] - matches[n*2],
											pass_replace);
							query_text = updated;
							query_len = strlen(query_text);
							break;
						}
					}
				}
			}
		}
		yajl_add_string_val(gen, "query", query_text, query_len);
	}
	else
	{
		if (cmd != NULL && strlen(cmd) != 0)
		{
			yajl_add_string_val(gen, "query", cmd, strlen(cmd));
		}
		else
		{
			yajl_add_string_val(gen, "query", "n/a", strlen("n/a"));
		}
	}

	ssize_t res = -2;
	yajl_gen_status stat = yajl_gen_map_close(gen); // close the object
	if (stat == yajl_gen_status_ok) // all is good write the buffer out
	{
		//will add the delimiter to the buffer
		yajl_gen_reset(gen, "\n");
		const unsigned char *text = NULL;
		size_t len = 0;
		yajl_gen_get_buf(gen, &text, &len);
		// print the json
		res = writer->write((const char *)text, len);		
	}
	yajl_gen_free(gen); // free the generator
	return res;
}

ThdSesData::ThdSesData(THD *pTHD, StatementSource source)
      : m_pThd (pTHD), m_CmdName(NULL), m_UserName(NULL),
        m_objIterType(OBJ_NONE), m_tables(NULL), m_firstTable(true),
        m_tableInf(NULL), m_index(0), m_isSqlCmd(false),
	m_port(-1), m_source(source), m_errorCode(0), m_setErrorCode(false)
{
	m_CmdName = retrieve_command (m_pThd, m_isSqlCmd);
	m_UserName = retrieve_user (m_pThd);

	m_peerInfo = retrieve_peerinfo(m_pThd);
	if (m_peerInfo && m_peerInfo->pid == 0)
	{
		// not UDS, get remote port
		m_port = Audit_formatter::thd_client_port(m_pThd);
	}
}

void ThdSesData::storeErrorCode()
{
	uint code = 0;
	if (Audit_formatter::thd_error_code(m_pThd, code))
	{
		setErrorCode(code);
	}
}

bool ThdSesData::startGetObjects()
{
	// reset vars as this may be called multiple times
	m_objIterType = OBJ_NONE;
	m_tables = NULL;
	m_firstTable = true;
	m_index = 0;
	m_tableInf = Audit_formatter::getQueryCacheTableList1(getTHD());
	int command = Audit_formatter::thd_inst_command(getTHD());
	LEX *pLex = Audit_formatter::thd_lex(getTHD());
	// query cache case
	if (pLex && command == COM_QUERY && m_tableInf && m_tableInf->num_of_elem > 0)
	{
		m_objIterType = OBJ_QUERY_CACHE;
		return true;
	}
	const char *cmd = getCmdName();
	// commands which have single database object
	if (strcmp(cmd,"Init DB") == 0
			|| strcmp(cmd, "SHOW TABLES") == 0
			|| strcmp(cmd, "SHOW TABLE") == 0)
	{
		if (Audit_formatter::thd_db(getTHD()))
		{
			m_objIterType = OBJ_DB;
			return true;
		}
		return false;
	}
	// only return query tables if command is COM_QUERY
	// TODO: check if other commands can also generate query tables
	// such as "show fields"
	if (   pLex
	    && (   command == COM_QUERY
	        || (command == COM_STMT_EXECUTE && strcmp(cmd, "Execute") != 0))
	    && pLex->query_tables)
	{
		m_tables = pLex->query_tables;
		m_objIterType = OBJ_TABLE_LIST;
		return true;
	}
	// no objects
	return false;
}

bool ThdSesData::getNextObject(const char **db_name, const char **obj_name, const char **obj_type)
{
	switch(m_objIterType)
	{
	case OBJ_DB:
	{
		if (m_firstTable)
		{
			*db_name = Audit_formatter::thd_db(getTHD());
			*obj_name = NULL;
			if (obj_type)
			{
				*obj_type = "DATABASE";
			}
			m_firstTable = false;
			return true;
		}
		return false;
	}
	case OBJ_QUERY_CACHE:
	{
		if (m_index < m_tableInf->num_of_elem &&
				m_index < MAX_NUM_QUERY_TABLE_ELEM)
		{
			*db_name = m_tableInf->db[m_index];
			*obj_name = m_tableInf->table_name[m_index];
			if (obj_type)
			{
				*obj_type = m_tableInf->object_type[m_index];
			}
			m_index++;
			return true;
		}
		return false;
	}
	case OBJ_TABLE_LIST:
	{
		if (m_tables)
		{
			*db_name = Audit_formatter::table_get_db_name(m_tables);
			*obj_name = Audit_formatter::table_get_name(m_tables);
			if (obj_type)
			{
				// object is a view if it view command (alter_view, drop_view ..)
				// and first object or view field is populated
				if ((m_firstTable && strstr(getCmdName(), "_view") != NULL) ||
						Audit_formatter::table_is_view(m_tables))
				{
					*obj_type = "VIEW";
					m_firstTable = false;
				}
				else
				{
					*obj_type = "TABLE";
				}
			}
			m_tables = m_tables->next_global;
			return true;
		}
		return false;
	}
	default:
		return false;
	}
}

const unsigned long ThdSesData::getPeerPid() const
{
	return (m_peerInfo != NULL ? m_peerInfo->pid : 0L);
}

const char *ThdSesData::getAppName() const
{
	return (m_peerInfo != NULL ? m_peerInfo->appName : NULL);
}

const char *ThdSesData::getOsUser() const
{
	return (m_peerInfo != NULL ? m_peerInfo->osUser : NULL);
}

pcre *Audit_json_formatter::regex_compile(const char *str)
{
	const char *error;
	int erroffset;
	static const int regex_flags =
		PCRE_DOTALL | PCRE_UTF8 | PCRE_CASELESS | PCRE_DUPNAMES;

	pcre *re = pcre_compile(str, regex_flags, &error, &erroffset, NULL);
	if (!re)
	{
		sql_print_error("%s unable to compile regex [%s]. offset: %d message: [%s].",
				AUDIT_LOG_PREFIX, str, erroffset, error);
	}
	return re;
}

bool Audit_json_formatter::compile_password_masking_regex(const char *str)
{
	// first free existing
	if (m_password_mask_regex_compiled)
	{
		m_password_mask_regex_compiled = false;
		// small sleep to let threads complete regexec
		my_sleep(10 * 1000);
		pcre_free(m_password_mask_regex_preg);
	}

	bool success = false; // default is error (case of empty string)
	if (NULL != str && str[0] != '\0')
	{
		m_password_mask_regex_preg = regex_compile(str);
		if (m_password_mask_regex_preg)
		{
			m_password_mask_regex_compiled = true;
			success = true;
		}
	}
	return success;
}
