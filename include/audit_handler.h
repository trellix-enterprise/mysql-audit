/*
 * audit_handler.h
 *
 *  Created on: Feb 6, 2011
 *      Author: guyl
 */

#ifndef AUDIT_HANDLER_H_
#define AUDIT_HANDLER_H_

#include "mysql_inc.h"
#include <yajl/yajl_gen.h>

#ifndef PCRE_STATIC
#define PCRE_STATIC
#endif

#include <pcre.h>

#define AUDIT_LOG_PREFIX "McAfee Audit Plugin:"
#define AUDIT_PROTOCOL_VERSION "1.0"

#if !defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 50709
// For locking we use the native lock routines provided by MySQL.
// The data types and functions for native locking changed at 5.7.x.
// Try to hide this with macros.
#define rw_lock_t	native_rw_lock_t
#define rw_rdlock	native_rw_rdlock
#define rw_wrlock	native_rw_wrlock
#define rw_unlock	native_rw_unlock
#define rwlock_destroy	native_rw_destroy
#define my_rwlock_init(lock, unused)	native_rw_init(lock)
#endif

class THD;

#define MAX_NUM_QUERY_TABLE_ELEM 100
typedef struct _QueryTableInf {
	int num_of_elem;
	char *db[MAX_NUM_QUERY_TABLE_ELEM];
	char *table_name[MAX_NUM_QUERY_TABLE_ELEM];
	const char *object_type[MAX_NUM_QUERY_TABLE_ELEM];
} QueryTableInf;

#define MAX_NUM_QUEUE_ELEM 1024
typedef struct _THDPRINTED {
	size_t cur_index;
	char is_thd_printed_queue[MAX_NUM_QUEUE_ELEM];
} THDPRINTED;

struct PeerInfo {
	unsigned long pid;
	enum { MAX_APP_NAME_LEN = 128, MAX_USER_NAME_LEN = 128 };
	char appName[MAX_APP_NAME_LEN + 1];
	char osUser[MAX_USER_NAME_LEN + 1];	// allow lots, in case from LDAP or some such
	PeerInfo() : pid(0) {
		memset(appName, 0, sizeof appName);
		memset(osUser, 0, sizeof osUser);
	}
};

PeerInfo *retrieve_peerinfo(THD *thd);

const char *retrieve_command(THD *thd, bool& is_sql_cmd);
typedef size_t OFFSET;

#define MAX_COMMAND_CHAR_NUMBERS 40
#define MAX_COM_STATUS_VARS_RECORDS 512

// mysql max identifier is 64 so 2*64 + . and null
#define MAX_OBJECT_CHAR_NUMBERS 131
#define MAX_USER_CHAR_NUMBERS 20
#define MAX_NUM_OBJECT_ELEM 256
#define MAX_NUM_USER_ELEM 256

/**
 * The struct used to hold offsets. We should have one per version.
 */
typedef struct ThdOffsets {
	const char *version;
	const char *md5digest;
	OFFSET query_id;
	OFFSET thread_id;
	OFFSET main_security_ctx;
	OFFSET command;
	OFFSET lex;
	OFFSET lex_comment;
	OFFSET sec_ctx_user;
	OFFSET sec_ctx_host;
	OFFSET sec_ctx_ip;
	OFFSET sec_ctx_priv_user;
	OFFSET db;
	OFFSET killed;
	OFFSET client_capabilities;
	OFFSET pfs_connect_attrs;
	OFFSET pfs_connect_attrs_length;
	OFFSET pfs_connect_attrs_cs;
	OFFSET net;
	OFFSET lex_m_sql_command;
	OFFSET uninstall_cmd_comment;
	OFFSET found_rows;
	OFFSET sent_row_count;
	OFFSET row_count_func;
	OFFSET stmt_da;
	OFFSET da_status;
	OFFSET da_sql_errno;
} ThdOffsets;

/*
 * The offsets array
 */
extern const ThdOffsets thd_offsets_arr[];
extern const size_t thd_offsets_arr_size;

/*
 * On  success,  the  number of bytes written are returned (zero indicates nothing was written).  On error, -1 is returned,
 */
typedef ssize_t (*audit_write_func)(const char *, size_t);


/**
 * Interface for an io writer
 */
class IWriter {
public:
	virtual ~IWriter() {}
	// return negative on fail
	virtual ssize_t write(const char *data, size_t size) = 0;
	virtual ssize_t write_no_lock(const char *str, size_t size) = 0;
	// return 0 on success
	virtual int open(const char *io_dest, bool log_errors) = 0;
	virtual void close() = 0;
};

class ThdSesData {
public:
	// enum indicating from where the object list came from
	enum ObjectIterType { OBJ_NONE, OBJ_DB, OBJ_QUERY_CACHE, OBJ_TABLE_LIST };
	// enum indicating source of statement
	typedef enum { SOURCE_GENERAL, SOURCE_QUERY_CACHE } StatementSource;
	ThdSesData(THD *pTHD, StatementSource source = SOURCE_GENERAL);
	THD *getTHD() const { return m_pThd;}
	const char *getCmdName() const { return m_CmdName; }
	void setCmdName(const char *cmd) { m_CmdName = cmd; }
	const char *getUserName() { return m_UserName; }
	const unsigned long getPeerPid() const;
	const char *getAppName() const;
	const char *getOsUser() const;
	const int getPort() const { return m_port; }
	const StatementSource getStatementSource() const { return m_source; }
	void storeErrorCode();
	void setErrorCode(uint code) { m_errorCode = code; m_setErrorCode = true; }
	bool getErrorCode(uint & code) const { code = m_errorCode; return m_setErrorCode; }
	/**
	 * Start fetching objects. Return true if there are objects available.
	 */
	bool startGetObjects();
	/**
	 * Get next object. Return true if populated. False if there isn't an
	 * object available.
	 * Will point the passed pointers to point to db, name and type.
	 * obj_type is optional and may be null.
	 */
	bool getNextObject(const char **db_name, const char **obj_name, const char **obj_type);

private:
	THD *m_pThd;
	const char *m_CmdName;
	const char *m_UserName;
	bool m_isSqlCmd;
	enum ObjectIterType m_objIterType;
	// pointer for iterating tables
	TABLE_LIST *m_tables;
	// indicator if we are at the first table
	bool m_firstTable;
	// used for query cache iter
	QueryTableInf *m_tableInf;
	int m_index;

	// Statement source
	StatementSource m_source;

	PeerInfo *m_peerInfo;

	int m_port;	// TCP port of remote side

	uint m_errorCode;
	bool m_setErrorCode;

protected:
	ThdSesData(const ThdSesData&);
	ThdSesData &operator =(const ThdSesData&);
};

/**
 * Base for audit formatter
 */
class Audit_formatter {
public:
	virtual ~Audit_formatter() {}

	/**
	 * static offsets to use for fetching THD data.
	 * Set by the audit plugin during startup.
	 */
	static ThdOffsets thd_offsets;

	/**
	 * Format an audit event from the passed THD.
	 * Will write out its output using the audit_write_func.
	 *
	 * @return -1 on a failure
	 */
	virtual ssize_t event_format(ThdSesData *pThdData, IWriter *writer) = 0;
	/**
	 * Format a message when handler is started
	 * @return -1 on a failure
	 */
	virtual ssize_t start_msg_format(IWriter *writer) { return 0; }
	/**
	 * Format a message when handler is stopped
	 * @return -1 on a failure
	 */
	virtual ssize_t stop_msg_format(IWriter *writer) { return 0; }

	static const char *retrieve_object_type(TABLE_LIST *pObj);
	static QueryTableInf *getQueryCacheTableList1(THD *thd);

	// utility functions for fetching thd stuff
	static int thd_client_port(THD *thd);

	static inline my_thread_id thd_inst_thread_id(THD *thd)
	{
		return *(my_thread_id *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.thread_id);
	}
	static inline query_id_t thd_inst_query_id(THD *thd)
	{
		return *(query_id_t *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.query_id);
	}
	static inline Security_context *thd_inst_main_security_ctx(THD *thd)
	{
		return (Security_context *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.main_security_ctx);
	}

	static inline const char *thd_db(THD *thd)
	{
		if (! Audit_formatter::thd_offsets.db) // no offsets use compiled in header
		{
#if defined(MARIADB_BASE_VERSION) || MYSQL_VERSION_ID < 50709
			return thd->db;
#else
			return thd->db().str;
#endif
		}
		return *(const char **) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.db);
	}

	static inline int thd_killed(THD *thd)
	{
		if (! Audit_formatter::thd_offsets.killed) // no offsets use thd_killed function
		{
			return ::thd_killed(thd);
		}
		return *(int *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.killed);
	}

	static inline const char *thd_inst_main_security_ctx_user(THD *thd)
	{
		Security_context *sctx = thd_inst_main_security_ctx(thd);
		if (! Audit_formatter::thd_offsets.sec_ctx_user) // no offsets use compiled in header
		{
#if defined(MARIADB_BASE_VERSION) || MYSQL_VERSION_ID < 50709
			return sctx->user;
#else
			return sctx->user().str;
#endif
		}
		return *(const char **) (((unsigned char *) sctx)
				+ Audit_formatter::thd_offsets.sec_ctx_user);
	}

	static inline const char *thd_inst_main_security_ctx_host(THD *thd)
	{
		Security_context *sctx = thd_inst_main_security_ctx(thd);
		// check ip to understand if set, as host is first in the struct and may actually be set to 0
		// we expect to have offsets for both ip and host or for neither of them
		if (! Audit_formatter::thd_offsets.sec_ctx_ip)
		{
			// interface changed in 5.5.34 and 5.6.14 and up host changed to get_host()
			// see: http://bazaar.launchpad.net/~mysql/mysql-server/5.5/revision/4407.1.1/sql/sql_class.h
#if defined(MARIADB_BASE_VERSION)
			return sctx->host;
#else
			// MySQL
#if  MYSQL_VERSION_ID < 50534 || (MYSQL_VERSION_ID >= 50600 && MYSQL_VERSION_ID < 50614)
			return sctx->host;
#elif (MYSQL_VERSION_ID >= 50534 && MYSQL_VERSION_ID < 50600) \
	|| (MYSQL_VERSION_ID >= 50614 &&  MYSQL_VERSION_ID < 50709)
			return sctx->get_host()->ptr();
#else
			// interface changed again in 5.7
			return sctx->host().str;
#endif
#endif // ! defined(MARIADB_BASE_VERSION)
		}
		return *(const char **) (((unsigned char *) sctx)
				+ Audit_formatter::thd_offsets.sec_ctx_host);
	}

	static inline const char *thd_inst_main_security_ctx_ip(THD *thd)
	{
		Security_context *sctx = thd_inst_main_security_ctx(thd);
		if (! Audit_formatter::thd_offsets.sec_ctx_ip) // no offsets use compiled in header
		{
			// interface changed in 5.5.34 and 5.6.14 and up host changed to get_ip()
#if defined(MARIADB_BASE_VERSION)
			return sctx->ip;
#else
			// MySQL
#if  MYSQL_VERSION_ID < 50534 || (MYSQL_VERSION_ID >= 50600 && MYSQL_VERSION_ID < 50614)
			return sctx->ip;
#elif (MYSQL_VERSION_ID >= 50534 && MYSQL_VERSION_ID < 50600) \
	|| (MYSQL_VERSION_ID >= 50614 &&  MYSQL_VERSION_ID < 50709)
			return sctx->get_ip()->ptr();
#else
			// interface changed again in 5.7
			return sctx->ip().str;
#endif
#endif // ! defined(MARIADB_BASE_VERSION)
		}
		return *(const char **) (((unsigned char *) sctx)
				+ Audit_formatter::thd_offsets.sec_ctx_ip);
	}

	static inline const char *thd_inst_main_security_ctx_priv_user(THD *thd)
	{
		Security_context *sctx = thd_inst_main_security_ctx(thd);
		if (! Audit_formatter::thd_offsets.sec_ctx_priv_user) // no offsets use compiled in header
		{
#if defined(MARIADB_BASE_VERSION) || MYSQL_VERSION_ID < 50709
			return sctx->priv_user;
#else
			return sctx->priv_user().str;
#endif
		}
		// in 5.5 and up priv_user is an array (char priv_user[USERNAME_LENGTH])
		return (const char *) (((unsigned char *) sctx)
				+ Audit_formatter::thd_offsets.sec_ctx_priv_user);
	}

	static inline int thd_inst_command(THD *thd)
	{
		return *(int *) (((unsigned char *) thd) + Audit_formatter::thd_offsets.command);
	}

	static inline LEX *thd_lex(THD *thd)
	{
		return *(LEX **) (((unsigned char *) thd) + Audit_formatter::thd_offsets.lex);
	}

#if !defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 50709
	//in mysql 5.7 capabilities flag moved to protocol. We use the capabilities offset to point to m_protocol
	//and get from protocol the capabilities flag
	static inline ulong thd_client_capabilities(THD *thd)
	{
		if (! Audit_formatter::thd_offsets.client_capabilities)
		{
			//no offsets - return 0
			return 0;
		}
		Protocol * prot = *(Protocol **) (((unsigned char *) thd) + Audit_formatter::thd_offsets.client_capabilities);
		if(!prot)
		{
			return 0;
		}
		return prot->get_client_capabilities();
	}
#else
	static inline ulong thd_client_capabilities(THD *thd)
	{
		if (! Audit_formatter::thd_offsets.client_capabilities)
		{
			//no offsets - return 0
			return 0;
		}
		return *(ulong *) (((unsigned char *) thd) + Audit_formatter::thd_offsets.client_capabilities);
	}
#endif

	static inline const char * pfs_connect_attrs(void * pfs)
	{
		if (! Audit_formatter::thd_offsets.pfs_connect_attrs || pfs == NULL)
		{
			//no offsets - return null
			return NULL;
		}
		const char **pfs_pointer = (const char **) (((unsigned char *) pfs) + Audit_formatter::thd_offsets.pfs_connect_attrs);

		return *pfs_pointer;
	}

	static inline uint pfs_connect_attrs_length(void * pfs)
	{
		if (! Audit_formatter::thd_offsets.pfs_connect_attrs_length || pfs == NULL)
		{
			//no offsets - return 0
			return 0;
		}
		return *(uint *) (((unsigned char *) pfs) + Audit_formatter::thd_offsets.pfs_connect_attrs_length);
	}
  
static inline const CHARSET_INFO * pfs_connect_attrs_cs(void * pfs)
{
	if (! Audit_formatter::thd_offsets.pfs_connect_attrs_cs || pfs == NULL)
	{
		//no offsets - return null
		return NULL;
	}    
#if (!defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 50600) || (defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 100010)
	/**
	 * m_session_connect_attrs_cs changed to: m_session_connect_attrs_cs_number
	 * in 5.6.15 and up, 5.7 and mariadb 10.0.11 and up, and 10.1.
	 * see: storage/perfschema/table_session_connect.cc
	 * and: storage/perfschema/pfs_instr.h
	 */
	static bool first = true;
	static int major, minor, patch;

	if (first)
	{
		sscanf(server_version, "%d.%d.%d", & major, & minor, & patch);
		// sql_print_information("Audit_plugin: extracted version: %d.%d.%d",
		//			major, minor, patch);
	}

	if (   ( major == 5  && ( (minor == 6 && patch >= 15) || minor >= 7) )		// MySQL
	    || ( major == 10 && ( (minor == 0 && patch >= 11) || minor >= 1) ) )	// MariaDB
	{
		uint cs_number = *(uint *) (((unsigned char *) pfs) + Audit_formatter::thd_offsets.pfs_connect_attrs_cs);
		if (!cs_number)
		{
			return NULL;

		} 
		return get_charset(cs_number, MYF(0));
	}
	else
#endif
	{
		return *(const CHARSET_INFO **) (((unsigned char *) pfs) + Audit_formatter::thd_offsets.pfs_connect_attrs_cs);
	}
}

	static inline int thd_client_fd(THD *thd)
	{
		if (! Audit_formatter::thd_offsets.net)
		{
			return -1;
		}
		NET *net = ((NET *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.net));
		// get the socket for the peer
		int sock = -1;
		if (net->vio != NULL)	// MySQL 5.7.17 - this can happen. :-(
		{
#if MYSQL_VERSION_ID < 50600
			sock = net->vio->sd;
#else
			sock = net->vio->mysql_socket.fd;
#endif
		}

		return sock;
	}

	static inline ulonglong thd_found_rows(THD *thd)
	{
		if (Audit_formatter::thd_offsets.found_rows == 0)
		{
			return 0;
		}

		ulonglong *rows = ((ulonglong *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.found_rows));

		return  *rows;
	}

	static inline unsigned long thd_sent_row_count(THD *thd)
	{
		if (Audit_formatter::thd_offsets.sent_row_count == 0)
		{
			return 0;
		}

		ha_rows *rows = ((ha_rows *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.sent_row_count));

		return (unsigned long) *rows;
	}

	static inline longlong thd_row_count_func(THD *thd)
	{
		if (Audit_formatter::thd_offsets.row_count_func == 0)
		{
			return -1;
		}

		longlong *rows = ((longlong *) (((unsigned char *) thd)
				+ Audit_formatter::thd_offsets.row_count_func));

		return *rows;
	}

	static inline bool thd_error_code(THD *thd, uint & code)
	{
#if MYSQL_VERSION_ID >= 50534

		if ( Audit_formatter::thd_offsets.stmt_da == 0      ||
		     Audit_formatter::thd_offsets.da_status == 0    ||
		     Audit_formatter::thd_offsets.da_sql_errno == 0 )
		{
			return false;
		}

		Diagnostics_area **stmt_da = ((Diagnostics_area **) (((unsigned char *) thd)
						+ Audit_formatter::thd_offsets.stmt_da));

		enum Diagnostics_area::enum_diagnostics_status *status =
			((enum Diagnostics_area::enum_diagnostics_status *) (((unsigned char *) (*stmt_da))
						+ Audit_formatter::thd_offsets.da_status));

		uint *sql_errno = ((uint *) (((unsigned char *) (*stmt_da))
						+ Audit_formatter::thd_offsets.da_sql_errno));

		if (*status == Diagnostics_area::DA_OK  ||
			*status == Diagnostics_area::DA_EOF	)
		{
			code = 0;
			return true;
		}
		else if (*status == Diagnostics_area::DA_ERROR)
		{
			code = *sql_errno;
			return true;
		}
		else // DA_EMPTY, DA_DISABLE
		{
			return false;
		}
#else
		return false;
#endif
	}

#if !defined(MARIADB_BASE_VERSION) && MYSQL_VERSION_ID >= 50709
	static inline Sql_cmd_uninstall_plugin* lex_sql_cmd(LEX *lex)
	{
		return *(Sql_cmd_uninstall_plugin **) (((unsigned char *) lex) + Audit_formatter::thd_offsets.lex_m_sql_command);
	}
#endif

	// we don't use get_db_name() as when we call it view may be not null
	// and it may return an invalid value for view_db
	static inline const char *table_get_db_name(TABLE_LIST *table)
	{
		return table->db;
	}

	static inline const char *table_get_name(TABLE_LIST *table)
	{
		return table->table_name;
	}

	static inline bool table_is_view(TABLE_LIST *table)
	{
		return table->view_tables != 0;
	}
};


/**
 * Format the audit even in json format
 */
class Audit_json_formatter: public Audit_formatter {
public:
	static const char *DEF_MSG_DELIMITER;

	Audit_json_formatter()
		: m_msg_delimiter(NULL),
		m_write_start_msg(true),
		m_write_sess_connect_attrs(true),
		m_write_client_capabilities(false),
		m_write_socket_creds(true),
		m_password_mask_regex_preg(NULL),
		m_password_mask_regex_compiled(false),
		m_perform_password_masking(NULL)
	{

	}

	virtual ~Audit_json_formatter()
	{
		if (m_password_mask_regex_preg)
		{
			m_password_mask_regex_compiled = false;
			pcre_free(m_password_mask_regex_preg);
			m_password_mask_regex_preg = NULL;
		}
	}

	virtual ssize_t event_format(ThdSesData *pThdData, IWriter *writer);
	virtual ssize_t start_msg_format(IWriter *writer);

	/**
	 * Utility method used to compile a regex program.
	 * Will compile and log errors if necessary.
	 * Return null if fails
	 */
	static pcre *regex_compile(const char *str);

	/**
	 * Compile password masking regex
	 * Return true on success
	 */
	bool compile_password_masking_regex(const char *str);

	/**
	 * Boolean indicating if to log start msg.
	 * Public so sysvar can update.
	 */
	my_bool m_write_start_msg;
	
	/**
	 * include session oonnect attributes
	 * Public so sysvar can update
	 */
	my_bool m_write_sess_connect_attrs;

	/**
	* include client capabilities
	* Public for sysvar
	*/
	my_bool m_write_client_capabilities;

	/**
	 * include socket credentials from Unix Domain Socket
	 * Public for sysvar
	 */
	my_bool m_write_socket_creds;

	/**
	 * Callback function to determine if password masking should be performed
	 */
	my_bool (*m_perform_password_masking)(const char *cmd);

	/**
	 * Message delimiter. Should point to a valid json string
	 * (supporting the json escapping format).
	 * Will only be checked at the start. Public so can be set by sysvar.
	 *
	 * We only support a delimiter up to 32 chars
	 */
	char *m_msg_delimiter;

protected:

	Audit_json_formatter& operator =(const Audit_json_formatter& b);
	Audit_json_formatter(const Audit_json_formatter& );

	/**
	 * Boolean indicating if password masking regex is compiled
	 */
	my_bool m_password_mask_regex_compiled;

	/**
	 * Regex used for password masking
	 */
	pcre *m_password_mask_regex_preg;
};

/**
 * Base class for audit handlers. Provides basic locking setup.
 */
class Audit_handler {
public:
	static const size_t MAX_AUDIT_HANDLERS_NUM = 4;
	static const size_t JSON_FILE_HANDLER = 1;
	static const size_t JSON_SOCKET_HANDLER = 3;

	static Audit_handler *m_audit_handler_list[];

	/**
	 * Will iterate the handler list and log using each handler
	 */
	static void log_audit_all(ThdSesData *pThdData);

	/**
	 * Will iterate the handler list and stop all handlers
	 */
	static void stop_all();

	Audit_handler() :
		m_initialized(false), m_enabled(false), m_print_offset_err(true),
		m_formatter(NULL), m_failed(false), m_log_io_errors(true)
	{
	}

	virtual ~Audit_handler()
	{
		if (m_initialized)
		{
			rwlock_destroy(&LOCK_audit);
			pthread_mutex_destroy(&LOCK_io);
		}
	}

	/**
	 * Should be called to initialize.
	 * We don't init in constructor in order to provide indication if
	 * pthread stuff failed init.
	 *
	 * @frmt the formatter to use in this handler (does not manage
	 * destruction of this object)
	 * @return 0 on success
	 */
	int init(Audit_formatter *frmt)
	{
		m_formatter = frmt;
		if (m_initialized)
		{
			return 0;
		}

		int res = my_rwlock_init(&LOCK_audit, NULL);
		if (res)
		{
			return res;
		}

		res = pthread_mutex_init(&LOCK_io, MY_MUTEX_INIT_SLOW);;
		if (res)
		{
			return res;
		}

		m_initialized = true;
		return res;
	}

	bool is_init()
	{
		return m_initialized;
	}

	void set_enable(bool val);

	bool is_enabled()
	{
		return m_enabled;
	}

	/**
	 * will close and start the handler
	 */
	void flush();

	/**
	 * Will get relevant shared lock and call internal method of handler
	 */
	void log_audit(ThdSesData *pThdData);

	/**
	 * Public so can be configured via sysvar
	 */
	unsigned int m_retry_interval;

protected:
	Audit_formatter *m_formatter;
	virtual void handler_start();
	// wiil call internal method and set failed as needed
	bool handler_start_nolock();
	virtual void handler_stop();
	virtual bool handler_start_internal() = 0;
	virtual void handler_stop_internal() = 0;
	virtual bool handler_log_audit(ThdSesData *pThdData) = 0;
	bool m_initialized;
	bool m_enabled;
	bool m_failed;
	bool m_log_io_errors;
	time_t m_last_retry_sec_ts;
	inline void set_failed()
	{
		time(&m_last_retry_sec_ts);
		m_failed = true;
		m_log_io_errors = false;
	}
	inline bool is_failed_now()
	{
		return m_failed && (m_retry_interval < 0 ||
				difftime(time(NULL), m_last_retry_sec_ts) > m_retry_interval);
	}
	// override default assignment and copy to protect against
	// creating additional instances
	Audit_handler & operator=(const Audit_handler&);
	Audit_handler(const Audit_handler&);
	// lock io 
	pthread_mutex_t LOCK_io;
private:
	// bool indicating if to print offset errors to log or not
	bool m_print_offset_err;	
	// audit (enable) lock
	rw_lock_t LOCK_audit;
	inline void lock_shared()
	{
		rw_rdlock(&LOCK_audit);
	}
	inline void lock_exclusive()
	{
		rw_wrlock(&LOCK_audit);
	}
	inline void unlock()
	{
		rw_unlock(&LOCK_audit);
	}
};

/**
 * Base class for handler which have io and need a lock
 */
class Audit_io_handler: public Audit_handler, public IWriter {
public:
	Audit_io_handler()
		: m_io_dest(NULL), m_io_type(NULL)
	{
	}

	virtual ~Audit_io_handler()
	{
	}


	/**
	 * target we write to (socket/file). Public so we update via sysvar
	 */
	char *m_io_dest;
	
	inline ssize_t write(const char *data, size_t size) 
	{
		pthread_mutex_lock(&LOCK_io);
		ssize_t res = write_no_lock(data, size);
		pthread_mutex_unlock(&LOCK_io);	//release the IO lock
		return res;
	}		

protected:
	/**
	 * Will format using the writer
	 */
	virtual bool handler_log_audit(ThdSesData *pThdData);
	virtual bool handler_start_internal();
	virtual void handler_stop_internal();
	// used for logging messages
	const char *m_io_type;
};

class Audit_file_handler: public Audit_io_handler {
public:

	Audit_file_handler() :
		m_sync_period(0), m_log_file(NULL), m_sync_counter(0), m_bufsize(0)
	{
		m_io_type = "file";
	}

	virtual ~Audit_file_handler()
	{
	}

	/**
	 * The period to use for syncing to the file system. 0 means we don't sync.
	 * 1 means each write we sync. Larger than 1 means every sync_period we sync.
	 *
	 * We leave this public so the mysql sysvar function can update this variable directly.
	 */
	unsigned int m_sync_period;

	/**
	 * The buf size used by the file stream. 0 = use default,
	 * negative or 1 = no buffering
	 */
	long m_bufsize;

	/**
	 * Write function we pass to formatter
	 */
	ssize_t write_no_lock(const char *data, size_t size);

	void close();

	int open(const char *io_dest, bool m_log_errors);
	// static void print_sleep(THD *thd, int delay_ms);
protected:
	// override default assignment and copy to protect against creating
	// additional instances
	Audit_file_handler & operator=(const Audit_file_handler&);
	Audit_file_handler(const Audit_file_handler&);
	
	FILE *m_log_file;
	// the period to use for syncing
	unsigned int m_sync_counter;
};

class Audit_socket_handler: public Audit_io_handler {
public:

	Audit_socket_handler() :
		m_vio(NULL), m_connect_timeout(1), m_write_timeout(0),
		m_log_with_error_severity(false)
	{
		m_io_type = "socket";
	}

	virtual ~Audit_socket_handler()
	{
	}


	/**
	 * Connect timeout in secconds
	 */
	unsigned int m_connect_timeout;

	/**
	 * Write function we pass to formatter
	 */
	ssize_t write_no_lock(const char *data, size_t size);

	void close();

	int open(const char *io_dest, bool log_errors);

	unsigned long m_write_timeout; // write timeout in microseconds
protected:
	// override default assignment and copy to protect against creating additional instances
	Audit_socket_handler & operator=(const Audit_socket_handler&);
	Audit_socket_handler(const Audit_socket_handler&);
	
	// Vio we write to
	// define as void* so we don't access members directly
	void *m_vio;

	// log using error severity only the second time same issue occurs
	bool m_log_with_error_severity;
};

#endif /* AUDIT_HANDLER_H_ */
