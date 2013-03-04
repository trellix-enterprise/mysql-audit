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
//for definition of sockaddr_un
#include <sys/un.h>
#include "static_assert.h"



/**
 * Will write into buff the date prefix for txt formatter. Return the number of bytes written
 * (not including null terminate).
 */
static int log_date_prefix(char * buff, size_t buff_size)
{
    struct tm tm_tmp;
    time_t result= time(NULL);
    localtime_r(&result, &tm_tmp);
    //my_snprintf is limited regarding formatting but sufficient for this
    return my_snprintf(buff, buff_size, "%02d%02d%02d %2d:%02d:%02d: ",
                    tm_tmp.tm_year % 100,
                    tm_tmp.tm_mon+1,
                    tm_tmp.tm_mday,
                    tm_tmp.tm_hour,
                    tm_tmp.tm_min,
                    tm_tmp.tm_sec);
}


//utility macro to log also with a date as a prefix
#define log_with_date(f, ...) do{\
    struct tm tm_tmp;\
    time_t result= time(NULL);\
    localtime_r(&result, &tm_tmp);\
    fprintf(f, "%02d%02d%02d %2d:%02d:%02d: ",\
                    tm_tmp.tm_year % 100,\
                    tm_tmp.tm_mon+1,\
                    tm_tmp.tm_mday,\
                    tm_tmp.tm_hour,\
                    tm_tmp.tm_min,\
                    tm_tmp.tm_sec);\
    fprintf(f, __VA_ARGS__);\
}while(0)


//initialize static stuff
ThdOffsets Audit_formatter::thd_offsets = { 0 };
Audit_handler * Audit_handler::m_audit_handler_list[Audit_handler::MAX_AUDIT_HANDLERS_NUM];
const char * Audit_json_formatter::DEF_MSG_DELIMITER = "\\n";

#define C_STRING_WITH_LEN(X) ((char *) (X)), ((size_t) (sizeof(X) - 1))


const char *  Audit_formatter::retrive_object_type (TABLE_LIST *pObj)
{
    if (pObj->view)
	{
		return "VIEW";
	}	
	return "TABLE";
}


void Audit_handler::stop_all()
{
    for (int i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
    {
        if (m_audit_handler_list[i] != NULL)
        {
            m_audit_handler_list[i]->set_enable(false);
        }
    }
}

void Audit_handler::log_audit_all(ThdSesData *pThdData)
{
    for (int i = 0; i < MAX_AUDIT_HANDLERS_NUM; ++i)
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
    if (m_enabled == val) //we are already enabled simply return
    {
        unlock();
        return;
    }
    m_enabled = val;
    if (m_enabled)
    {
        //call the startup of the handler
        handler_start();
    }
    else
    {
        //call the cleanup of the handler
        handler_stop();
    }
    unlock();
}

void Audit_handler::flush()
{
	lock_exclusive();
    if (!m_enabled) //if not running we don't flush
    {
        unlock();
        return;
    }
    //call the cleanup of the handler
    handler_stop();
    //call the startup of the handler
    handler_start();          
	sql_print_information("%s Log flush complete.", AUDIT_LOG_PREFIX);
    unlock();
}

void Audit_handler::log_audit(ThdSesData *pThdData)
{
    lock_shared();
    if (!m_enabled)
    {
        unlock();
        return;
    }
    //sanity check that offsets match
	//we can also consider using secutiry context function to do some sanity checks
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
    {//offsets are good
        m_print_offset_err = true; //mark to print offset err to log incase we encounter in the future
        handler_log_audit(pThdData);
    }
    unlock();
}

ssize_t Audit_file_handler::write(const char * data, size_t size)
{
    return my_fwrite(m_log_file, (uchar *) data, size, MYF(0));
}

void Audit_file_handler::handler_start()
{
    pthread_mutex_lock(&LOCK_io);
    char format_name[FN_REFLEN];
    fn_format(format_name, m_filename, "", "", MY_UNPACK_FILENAME);
    m_log_file = my_fopen(format_name, O_RDWR | O_APPEND, MYF(0));
    if (!m_log_file)
    {
        sql_print_error(
                "%s unable to create %s: %s. audit file handler disabled!!",
                AUDIT_LOG_PREFIX, m_filename, strerror(errno));
        m_enabled = false;
    }
    else
    {
        ssize_t res = m_formatter->start_msg_format(this);
        /*
         sanity check of writing to the log. If we fail. We will print an erorr and disable this handler.
         */
        if (res < 0 || fflush(m_log_file) != 0)
        {
            sql_print_error(
                    "%s unable to write to %s: %s. Disabling audit handler.",
                    AUDIT_LOG_PREFIX, m_filename, strerror(errno));
            close_file();
            m_enabled = false;
        }
    }
    pthread_mutex_unlock(&LOCK_io);
}
void Audit_file_handler::handler_stop()
{
    pthread_mutex_lock(&LOCK_io);
    m_formatter->stop_msg_format(this);
    close_file();
    pthread_mutex_unlock(&LOCK_io);
}

void Audit_file_handler::handler_log_audit(ThdSesData *pThdData)
{
    pthread_mutex_lock(&LOCK_io);
    m_formatter->event_format(pThdData, this);
    if (++m_sync_counter >= m_sync_period && m_sync_period)
    {
        m_sync_counter = 0;
        //Note fflush() only flushes the user space buffers provided by the C library.
        //To ensure that the data is physically stored on disk the kernel buffers must be flushed too,
        //e.g. with sync(2) or fsync(2).
        fflush(m_log_file);
        int fd = fileno(m_log_file);
        my_sync(fd, MYF(MY_WME));
    }
    pthread_mutex_unlock(&LOCK_io);
}

/////////////////// Audit_socket_handler //////////////////////////////////

ssize_t Audit_socket_handler::write(const char * data, size_t size)
{
    if (strncmp(m_sockname, "dgram:", 6) == 0) {
        return send(sock, data, size, 0);
    } else {
        return vio_write((Vio*)m_vio, (const uchar *) data, size);
    }
}

void Audit_socket_handler::handler_start()
{
    pthread_mutex_lock(&LOCK_io);

    if (strncmp(m_sockname, "dgram:", 6) == 0) { //Datagram socket
        sock = socket(AF_UNIX,SOCK_DGRAM,0);
        if (sock < 0) {
            sql_print_error("%s unable to create DGRAM socket %s. audit socket handler disabled!!", AUDIT_LOG_PREFIX, strerror(errno));
            m_enabled = false;
            pthread_mutex_unlock(&LOCK_io);
            return;
        }
        struct sockaddr_un UNIXaddr;
        UNIXaddr.sun_family = AF_UNIX;
        strmake(UNIXaddr.sun_path, m_sockname+6, sizeof(UNIXaddr.sun_path)-1);
        if (my_connect(sock,(struct sockaddr *) &UNIXaddr, sizeof(UNIXaddr), m_connect_timeout)) {
            sql_print_error("%s unable to connect to DGRAM socket %s. err: %s. audit socket handler disabled!!", AUDIT_LOG_PREFIX, m_sockname, strerror(errno));
            m_enabled = false;
            pthread_mutex_unlock(&LOCK_io);
            return;
        }
        ssize_t res = m_formatter->start_msg_format(this);
        if (res < 0) { // sanity check of writing to the log. If we fail, print an error and disable this handler.
            sql_print_error("%s unable to write to DGRAM socket %s: %s. Disabling audit handler.", AUDIT_LOG_PREFIX, m_sockname, strerror(errno));
            m_enabled = false;
        }
    } else { //Stream socket
        sock = socket(AF_UNIX,SOCK_STREAM,0);
        if (sock < 0){
            sql_print_error("%s unable to create STREAM socket %s. audit socket handler disabled!!", AUDIT_LOG_PREFIX, strerror(errno));
            m_enabled = false;
            pthread_mutex_unlock(&LOCK_io);
            return;
        }

        //connect the socket
        m_vio= vio_new(sock, VIO_TYPE_SOCKET, VIO_LOCALHOST);
        struct sockaddr_un UNIXaddr;
        UNIXaddr.sun_family = AF_UNIX;
        strmake(UNIXaddr.sun_path, m_sockname, sizeof(UNIXaddr.sun_path)-1);
        if (my_connect(sock,(struct sockaddr *) &UNIXaddr, sizeof(UNIXaddr), m_connect_timeout)) {
          sql_print_error("%s unable to connect to STREAM socket %s. err: %s. audit socket handler disabled!!", AUDIT_LOG_PREFIX, m_sockname, strerror(errno));
          close_vio();
          m_enabled = false;
          pthread_mutex_unlock(&LOCK_io);
          return;
        }
        ssize_t res = m_formatter->start_msg_format(this);
        if (res < 0) { // sanity check of writing to the log. If we fail, print an error and disable this handler.
            sql_print_error("%s unable to write to STREAM socket %s: %s. Disabling audit handler.", AUDIT_LOG_PREFIX, m_sockname, strerror(errno));
            close_vio();
            m_enabled = false;
        }
    }
    pthread_mutex_unlock(&LOCK_io);
}

void Audit_socket_handler::handler_stop()
{
    pthread_mutex_lock(&LOCK_io);
    m_formatter->stop_msg_format(this);
    if (strncmp(m_sockname, "dgram:", 6) != 0) {
        close_vio();
    }
    pthread_mutex_unlock(&LOCK_io);
}

void Audit_socket_handler::handler_log_audit(ThdSesData *pThdData)
{
    pthread_mutex_lock(&LOCK_io);
    m_formatter->event_format(pThdData, this);
    pthread_mutex_unlock(&LOCK_io);
}

//////////////////////// Audit Socket handler end ///////////////////////////////////////////




static inline yajl_gen_status yajl_add_string(yajl_gen hand, const char * str)
{
    return yajl_gen_string(hand, (const unsigned char*)str, strlen(str));
}

static inline void yajl_add_string_val(yajl_gen hand, const char * name, const char* val)
{
	if(0 == val)
	{
		return; //we don't add NULL values to json
	}
    yajl_add_string(hand, name);
    yajl_add_string(hand, val);
}

static inline void yajl_add_string_val(yajl_gen hand, const char * name, const char* val, size_t val_len)
{
    yajl_add_string(hand, name);
    yajl_gen_string(hand, (const unsigned char*)val, val_len);
}

static inline void yajl_add_uint64(yajl_gen gen, const char * name, uint64 num)
{
    const size_t max_int64_str_len = 21;
    char buf[max_int64_str_len];
    snprintf(buf, max_int64_str_len, "%llu", num);
    yajl_add_string_val(gen, name, buf);
}
static inline void yajl_add_obj( yajl_gen gen,  const char *db,const char* ptype,const char * name =NULL)
{
    yajl_add_string_val(gen, "db", db);
    if (name)
    {
        yajl_add_string_val(gen, "name", name);
    }
    yajl_add_string_val(gen, "obj_type",ptype);
}

//will return a pointer to the query and set len with the length of the query
//starting with MySQL version 5.1.41 thd_query_string is added
#if MYSQL_VERSION_ID > 50140
extern "C" {
    MYSQL_LEX_STRING *thd_query_string(MYSQL_THD thd);
}
static const char * thd_query_str(THD * thd, size_t * len)
{
    MYSQL_LEX_STRING * str = thd_query_string(thd);
    if(str)
    {
        *len = str->length;
        return str->str;
    }
    *len = 0;
    return NULL;
}
#else
//we are being compiled against mysql version 5.1.40 or lower (our default compilation env)
//we still want to support thd_query_string if we are run on a version higher than 5.1.40, so we try to lookup the symbol
static LEX_STRING * (*thd_query_string_func)(THD *thd) = (LEX_STRING*(*)(THD*))dlsym(RTLD_DEFAULT, "thd_query_string");
static bool print_thd_query_string_func = true; //debug info print only once
static const char * thd_query_str(THD * thd, size_t * len)
{
    if(print_thd_query_string_func)
    {
        sql_print_information("%s thd_query_string_func: 0x%lx", AUDIT_LOG_PREFIX, (unsigned long)thd_query_string_func);
        print_thd_query_string_func = false;
    }
    if(thd_query_string_func)
    {
        MYSQL_LEX_STRING * str = thd_query_string_func(thd);
        if(str)
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


ssize_t Audit_json_formatter::event_format(ThdSesData* pThdData, IWriter * writer)
{
    unsigned long thdid = thd_get_thread_id(pThdData->getTHD());
    query_id_t qid = thd_inst_query_id(pThdData->getTHD());
	int command = thd_inst_command(pThdData->getTHD());

	
	Security_context * sctx = thd_inst_main_security_ctx(pThdData->getTHD());

    //initialize yajl
    yajl_gen gen = yajl_gen_alloc(&config, NULL);
    yajl_gen_map_open(gen);
    yajl_add_string_val(gen, "msg-type", "activity");
    //TODO: get the start date from THD (but it is not in millis. Need to think about how we handle this)
    //for now simply use the current time.
    //my_getsystime() time since epoc in 100 nanosec units. Need to devide by 1000*(1000/100) to reach millis
    uint64 ts = my_getsystime() / (10000);
    yajl_add_uint64(gen, "date", ts);
    yajl_add_uint64(gen, "thread-id", thdid);
    yajl_add_uint64(gen, "query-id", qid);
	yajl_add_string_val(gen, "user", sctx->user);
	yajl_add_string_val(gen, "priv_user", sctx->priv_user);
	yajl_add_string_val(gen, "host", sctx->host);
    yajl_add_string_val(gen, "ip", sctx->ip);    
    const char *cmd = pThdData->getCmdName();
    yajl_add_string_val(gen, "cmd", cmd);
    //get objects
    if(pThdData->startGetObjects())
    {
        yajl_add_string(gen, "objects");
        yajl_gen_array_open(gen);
        const char * db_name = NULL;
        const char * obj_name = NULL;
        const char * obj_type = NULL;
        while(pThdData->getNextObject(&db_name, &obj_name, &obj_type))
        {
            yajl_gen_map_open(gen);
            yajl_add_obj (gen, db_name, obj_type, obj_name );
            yajl_gen_map_close(gen);
        }
        yajl_gen_array_close(gen);
    }

    size_t qlen = 0;
    const char * query = thd_query_str(pThdData->getTHD(), &qlen);
    if (query && qlen > 0)
    {
		CHARSET_INFO *col_connection = Item::default_charset();
		if (strcmp (col_connection->csname,"utf8")!=0) {
			String sQuery (query,col_connection) ;
			pThdData->getTHD()->convert_string (&sQuery,col_connection,&my_charset_utf8_general_ci);
			yajl_add_string_val(gen, "query", sQuery.c_ptr_safe(), sQuery.length());
		}
		else
		{
			yajl_add_string_val(gen, "query",query, qlen);
		}
		
    }
    else 
    {
        if (cmd!=NULL && strlen (cmd)!=0)
        {
            yajl_add_string_val(gen, "query",cmd, strlen (cmd));
        }
        else 
        {
            yajl_add_string_val(gen, "query","n/a", strlen ("n/a"    ));
        }
    }
    ssize_t res = -2;
    yajl_gen_status stat = yajl_gen_map_close(gen); //close the object
    if(stat == yajl_gen_status_ok) //all is good write the buffer out
    {
        const unsigned char * text = NULL;
        unsigned int len = 0;
        yajl_gen_get_buf(gen, &text, &len);
        //print the json
        res = writer->write((const char *)text, len);
        if(res >= 0)
        {
            //TODO: use the msg_delimiter
            res = writer->write("\n", 1);
        }
        //my_fwrite(log_file, (uchar *) b.data, json_size(&b), MYF(0));
    }
    yajl_gen_free(gen); //free the generator
    return res;
}



ThdSesData::ThdSesData (THD *pTHD) :
        m_pThd (pTHD), m_CmdName(NULL), m_UserName(NULL),
        m_objIterType(OBJ_NONE), m_tables(NULL), m_firstTable(true),
        m_tableInf(NULL), m_index(0)
{
    m_CmdName = retrieve_command (m_pThd);    
    m_UserName = retrieve_user (m_pThd);
}

bool ThdSesData::startGetObjects()
{
    //reset vars as this may be called multiple times
    m_objIterType = OBJ_NONE;
    m_tables = NULL;
    m_firstTable = true;
    m_index = 0;
    m_tableInf =  Audit_formatter::getQueryCacheTableList1(getTHD());
    int command = Audit_formatter::thd_inst_command(getTHD());
    LEX * pLex = Audit_formatter::thd_lex(getTHD());
    //query cache case
    if(pLex && command == COM_QUERY && m_tableInf && m_tableInf->num_of_elem > 0)
    {
        m_objIterType = OBJ_QUERY_CACHE;
        return true;
    }
    const char *cmd = getCmdName();
    //commands which have single database object
    if (strcmp (cmd,"Init DB") ==0 || strcmp (cmd, "SHOW TABLES")== 0 || strcmp (cmd,  "SHOW TABLE")==0)
    {
        if(getTHD()->db)
        {
            m_objIterType = OBJ_DB;
            return true;
        }
        return false;
    }
    //only return query tabls if command is COM_QUERY
    //TODO: check if other commands can also generate query tables such as "show fields"
    if (pLex && command == COM_QUERY && pLex->query_tables)
    {
        m_tables = pLex->query_tables;
        m_objIterType = OBJ_TABLE_LIST;
        return true;
    }
    //no objects
    return false;
}

bool ThdSesData::getNextObject(const char ** db_name, const char ** obj_name, const char ** obj_type)
{
    switch(m_objIterType)
    {
        case OBJ_DB:
        {
            if(m_firstTable)
            {
                *db_name = getTHD()->db;
                *obj_name = NULL;
                if(obj_type)
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
            if(m_index < m_tableInf->num_of_elem &&
                    m_index< MAX_NUM_QUERY_TABLE_ELEM)
            {
                *db_name = m_tableInf->db[m_index];
                *obj_name = m_tableInf->table_name[m_index];
                if(obj_type)
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
            if(m_tables)
            {
                *db_name = m_tables->get_db_name();
                *obj_name = m_tables->get_table_name();
                if(obj_type)
                {
                    //object is a view if it view command (alter_view, drop_view ..)
                    //and first object or view field is populated
                    if((m_firstTable && strstr(getCmdName(), "_view") != NULL) ||
                            m_tables->view)
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
        default :
            return false;
    }
}
