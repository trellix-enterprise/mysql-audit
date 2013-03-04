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

#define AUDIT_LOG_PREFIX "Audit Plugin:"

class THD;

#define MAX_NUM_QUERY_TABLE_ELEM 100
typedef struct _QueryTableInf {
	int num_of_elem;
	char *db[MAX_NUM_QUERY_TABLE_ELEM];
	char *table_name[MAX_NUM_QUERY_TABLE_ELEM];
	const char *object_type [MAX_NUM_QUERY_TABLE_ELEM];
} QueryTableInf; 

#define MAX_NUM_QUEUE_ELEM 1024
typedef struct _THDPRINTED {
    size_t cur_index;
    char is_thd_printed_queue [MAX_NUM_QUEUE_ELEM];
} THDPRINTED;

#define MAX_COMMAND_CHAR_NUMBERS 40
const char * retrieve_command (THD * thd);
typedef size_t OFFSET;

#define MAX_COM_STATUS_VARS_RECORDS 512

//mysql max identifier is 64 so 2*64 + . and null
#define MAX_OBJECT_CHAR_NUMBERS 131
#define MAX_USER_CHAR_NUMBERS 20
const char * retrieve_user (THD * thd);
#define MAX_NUM_OBJECT_ELEM 256
#define MAX_NUM_USER_ELEM 256

/**
 * The struct usd to hold offsets. We should have one per version.
 */
typedef struct ThdOffsets
{
    const char * version;
	const char * md5digest;
    OFFSET query_id;
    OFFSET thread_id;
    OFFSET main_security_ctx;
    OFFSET command;
	OFFSET lex;
	OFFSET lex_comment;
} ThdOffsets;

/*
 * On  success,  the  number of bytes written are returned (zero indicates nothing was written).  On error, -1 is returned,
 */
typedef ssize_t (*audit_write_func)(const char *, size_t);


/**
 * Interface for an io writer
 */
class IWriter
{
public:
    virtual ~IWriter() {}
    virtual ssize_t write(const char * data, size_t size) = 0;
    inline ssize_t write_str(const char * str)
    {
        return write(str, strlen(str));
    }
};

class ThdSesData {
public:

    //enum indicating from where the object list came from
    enum ObjectIterType {OBJ_NONE, OBJ_DB, OBJ_QUERY_CACHE, OBJ_TABLE_LIST};
    ThdSesData(THD *pTHD);
    THD* getTHD () { return m_pThd;}
    const char * getCmdName () { return m_CmdName; }
    const char * getUserName () { return m_UserName; }
    /**
     * Start fetching objects. Return true if there are objects available.
     */
    bool startGetObjects();
    /**
     * Get next object. Return true if populated. False if there isn't an object available.
     * Will point the passed pointers to point to db, name and type.
     * obj_type is optional and may be null.
     */
    bool getNextObject(const char ** db_name, const char ** obj_name, const char ** obj_type);
private:
    THD *m_pThd;
    const char *m_CmdName;
    const char *m_UserName;
    enum ObjectIterType m_objIterType;
    //pointer for iterating tables
    TABLE_LIST * m_tables;
    //indicator if we are at the first table
    bool m_firstTable;
    //used for query cache iter
    QueryTableInf * m_tableInf;
    int m_index;
protected:
    ThdSesData (const ThdSesData& );
    ThdSesData &operator =(const ThdSesData& );
};
 
/**
 * Base for audit formatter
 */
class Audit_formatter
{
public:

    virtual ~Audit_formatter() {}

    /**
     * static offsets to use for fetching THD data. Set by the audit plugin during startup.
     */
    static ThdOffsets thd_offsets;

    /**
     * Format an audit event from the passed THD. Will write out its output using the audit_write_func.
     *
     * @return -1 on a failure
     */
    virtual ssize_t event_format(ThdSesData *pThdData, IWriter * writer) =0;
    /**
     * format a message when handler is started
     * @return -1 on a failure
     */
    virtual ssize_t start_msg_format(IWriter * writer) { return 0; }
    /**
     * format a message when handler is stopped
     * @return -1 on a failure
     */
    virtual ssize_t stop_msg_format(IWriter * writer) { return 0; }

	static const char * retrive_object_type (TABLE_LIST *pObj);
	static QueryTableInf* getQueryCacheTableList1 (THD *thd);
    //utility functions for fetching thd stuff
    static inline my_thread_id thd_inst_thread_id(THD * thd)
    {
        return *(my_thread_id *) (((unsigned char *) thd)
                + Audit_formatter::thd_offsets.thread_id);
    }
    static inline query_id_t thd_inst_query_id(THD * thd)
    {
        return *(query_id_t *) (((unsigned char *) thd)
                + Audit_formatter::thd_offsets.query_id);
    }
    static inline Security_context * thd_inst_main_security_ctx(THD * thd)
    {
        return (Security_context *) (((unsigned char *) thd)
                + Audit_formatter::thd_offsets.main_security_ctx);
    }
	static inline int thd_inst_command(THD * thd)
    {
        return *(int *) (((unsigned char *) thd) + Audit_formatter::thd_offsets.command);
    }

	static inline LEX* thd_lex(THD * thd)
    {
		return *(LEX**) (((unsigned char *) thd) + Audit_formatter::thd_offsets.lex);
    }

};


/**
 * Format the audit even in json format
 */
class Audit_json_formatter: public Audit_formatter
{
public:

    static const char * DEF_MSG_DELIMITER;

    Audit_json_formatter(): m_msg_delimiter(NULL)
    {
        config.beautify = 0;
        config.indentString = NULL;
    }
    virtual ~Audit_json_formatter() {}
    virtual ssize_t event_format(ThdSesData *pThdData, IWriter * writer);

    /**
     * Message delimiter. Should point to a valid json string (supporting the json escapping format).
     * Will only be checked at the start. Public so can be set by sysvar.
     *
     * We only support a delimiter up to 32 chars
     */
    char * m_msg_delimiter;

    /**
     * Configuration of yajl. Leave public so sysvar can update this directly.
     */
    yajl_gen_config config;
    
protected:

	Audit_json_formatter& operator =(const Audit_json_formatter& b) {};
	Audit_json_formatter(const Audit_json_formatter& ) {};

};

/**
 * Base class for audit handlers. Provides basic locking setup.
 */
class Audit_handler
{
public:



    static const size_t MAX_AUDIT_HANDLERS_NUM = 4;
    static const size_t JSON_FILE_HANDLER = 1;
    static const size_t JSON_SOCKET_HANDLER = 3;

    static Audit_handler * m_audit_handler_list[];

    /**
     * Will iterate the handler list and log using each handler
     */
    static void log_audit_all(ThdSesData *pThdData);

    /**
     * Will iterate the handler list and stop all handlers
     */
    static void stop_all();

    Audit_handler() :
        m_initialized(false), m_enabled(false), m_print_offset_err(true), m_formatter(NULL)
    {
    }

    virtual ~Audit_handler()
    {
        if (m_initialized)
        {
            rwlock_destroy(&LOCK_audit);
        }
    }

    /**
     * Should be called to initialize. We don't init in constructor in order to provide indication if
     * pthread stuff failed init.
     *
     * Will internally call handler_init();
     *
     * @frmt the formatter to use in this handler (does not manage distruction of this object)
     * @return 0 on success
     */
    int init(Audit_formatter * frmt)
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
        res = handler_init();
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
	
	/**
	 * will close and start the handler
	 */
	void flush();

    /**
     * Will get relevant shared lock and call internal method of handler
     */
    void log_audit(ThdSesData *pThdData);

protected:
    Audit_formatter * m_formatter;
    virtual void handler_start() = 0;
    virtual void handler_stop() = 0;
    virtual int handler_init() = 0;
    virtual void handler_log_audit(ThdSesData *pThdData) =0;
    bool m_initialized;
    bool m_enabled;
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
	Audit_handler & operator=(const Audit_handler&) {};
	Audit_handler(const Audit_handler&) {};
private:
    //bool indicating if to print offset errors to log or not
    bool m_print_offset_err;
};

/**
 * Base class for handler which have io and need a lock
 */
class Audit_io_handler: public Audit_handler, public IWriter
{
public:
    virtual ~Audit_io_handler()
    {
        if (m_initialized)
        {
            pthread_mutex_destroy(&LOCK_io);
        }
    }

protected:
    virtual int handler_init()
    {
        return pthread_mutex_init(&LOCK_io, MY_MUTEX_INIT_SLOW);
    }
    //mutex we need sync writes on file
    pthread_mutex_t LOCK_io;
};

class Audit_file_handler: public Audit_io_handler
{
public:

    Audit_file_handler() :
        m_log_file(NULL), m_sync_period(0), m_sync_counter(0), m_filename(NULL)
    {
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
     * File name of the file we write to. Public so sysvar function can update this directly.
     */
    char * m_filename;

    /**
     * Write function we pass to formatter
     */
    ssize_t write(const char * data, size_t size);
    //static void print_sleep (THD *thd, int delay_ms);
protected:
	Audit_file_handler & operator=(const Audit_file_handler&) {};
	Audit_file_handler(const Audit_file_handler&) {};
    virtual void handler_start();
    virtual void handler_stop();

    /**
     * Will acquire locks and call handler_write
     */
    virtual void handler_log_audit(ThdSesData *pThdData);
    FILE * m_log_file;
    //the period to use for syncing
    unsigned int m_sync_counter;
    void close_file()
    {
        if (m_log_file)
        {
            my_fclose(m_log_file, MYF(0));
        }
        m_log_file = NULL;
    }

};

class Audit_socket_handler: public Audit_io_handler
{
int sock;
public:

    Audit_socket_handler() :
        m_sockname(NULL), m_vio(NULL), m_connect_timeout(1)
    {
    }

    virtual ~Audit_socket_handler()
    {
    }

    /**
     * Socket name of the UNIX socket we write to. Public so sysvar function can update this directly.
     */
    char * m_sockname;

    /**
     * Connect timeout in secconds
     */
    unsigned int m_connect_timeout;

    /**
     * Write function we pass to formatter
     */
    ssize_t write(const char * data, size_t size);

protected:
	Audit_socket_handler & operator=(const Audit_socket_handler&) {};
	Audit_socket_handler(const Audit_socket_handler&) {};
    virtual void handler_start();
    virtual void handler_stop();

    /**
     * Will acquire locks and call handler_write
     */
    virtual void handler_log_audit(ThdSesData *pThdData);
    //Vio we write to
    //define as void* so we don't access members directly
    void * m_vio;
    void close_vio()
    {
        if (m_vio)
        {
            vio_close((Vio*)m_vio);
            vio_delete((Vio*)m_vio);
        }
        m_vio = NULL;
    }

};


#endif /* AUDIT_HANDLER_H_ */
