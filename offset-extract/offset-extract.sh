#!/bin/sh

if [ $# = 0 ]
then 	
	echo "Usage: $0 <mysqld executable> [optional mysqld symbols]"
	echo "Will extract offsets from mysqld. Requires gdb, md5sum and mysqld symbols."
	exit 1
fi

# Extract the version of mysqld

FULL_MYVER=`$1 --version | grep -P -o 'Ver\s+[\w\.-]+'| awk '{ print $2 }'`

# Extract the md5 digest

MYMD5=`md5sum -b $1 | awk -v Field=1 '{ print $1 }'`

MYVER="$FULL_MYVER"
if echo $FULL_MYVER | grep  'log' > /dev/null
then
	MYVER=`echo "$MYVER" | grep -P -o '.+(?=-log)'`
fi

COMMAND_MEMBER=command
THREAD_ID=thread_id
SEC_CONTEXT=main_security_ctx
USER=user
HOST=host
IP=ip
PRIV_USER=priv_user
DB=db
CLIENT_CAPS="print_offset THD client_capabilities"

# In 5.6 command member is named m_command
if echo $MYVER | grep -P '^(5\.6|5\.7|8\.|10\.)' > /dev/null
then
	COMMAND_MEMBER=m_command
	HAS_CONNECT_ATTRS=yes
fi

CONNECT_ATTRS_CS=m_session_connect_attrs_cs
# In 5.7 thread_id changed to m_thread_id. main_security_ctx changed to m_main_security_ctx
if echo $MYVER | grep -P '^(5\.7|8\.)' > /dev/null
then
	THREAD_ID=m_thread_id
	SEC_CONTEXT=m_main_security_ctx
	USER=m_user
	HOST=m_host
	IP=m_ip
	PRIV_USER=m_priv_user    
	DB=m_db
	# client capabilities has moved out THD in 5.7. Set to 0
	CLIENT_CAPS='print_offset THD m_protocol'      

	# comment which holds plugin name for uninstall moved into
	# a separate object
	HAS_LEX_SQL_CMD=yes
fi

# In 5.6.15 and up, 5.7 and mariabdb 10.0.11 and up, mariadb 10.1 
# m_session_connect_attrs_cs changed to m_session_connect_attrs_cs_number
if echo $MYVER | grep -P '^(5\.7|8\.|10\.[1-5]|5\.6\.(1[5-9]|[2-9][0-9])|10.0.(1[1-9]|[2-9][0-9]))' > /dev/null
then
	CONNECT_ATTRS_CS=m_session_connect_attrs_cs_number
fi

CONNECT_ATTRS=""
if [ -n "$HAS_CONNECT_ATTRS" ]
then  
	CONNECT_ATTRS="print_offset PFS_thread m_session_connect_attrs
print_offset PFS_thread m_session_connect_attrs_length
print_offset PFS_thread $CONNECT_ATTRS_CS
"
else
	CONNECT_ATTRS='printf ", 0, 0, 0"'
fi

if echo $MYVER | grep -P '^(5\.7|8\.4|8\.0)' > /dev/null
then
	if echo $MYVER | grep -P '^5\.7\.8' > /dev/null
	then
		FOUND_ROWS="print_offset THD limit_found_rows"
	else
		FOUND_ROWS="print_offset THD previous_found_rows"
	fi
else
	FOUND_ROWS="print_offset THD limit_found_rows"
fi

if echo $MYVER | grep -P '^5\.[15]' > /dev/null
then
	SENT_ROW_COUNT='print_offset THD sent_row_count'
else
	SENT_ROW_COUNT="print_offset THD m_sent_row_count"
fi

if echo $MYVER | grep -P '^5\.1' > /dev/null
then
	ROW_COUNT_FUNC='print_offset THD row_count_func'
else
	ROW_COUNT_FUNC='print_offset THD m_row_count_func'
fi

LEX_SQL=""
if [ -n "$HAS_LEX_SQL_CMD" ]
then
	LEX_SQL="print_offset LEX m_sql_cmd
print_offset Sql_cmd_uninstall_plugin m_comment"
else
	LEX_SQL='printf ", 0, 0"'
fi

# Exit status info 5.5, 5.6, 5.7
DA_STATUS="print_offset Diagnostics_area m_status"		# 5.5, 5.6, 5.7, mariadb 10.0 to 10.5
DA_SQL_ERRNO="print_offset Diagnostics_area m_sql_errno"	# 5.5, 5.6, mariadb 10.0 to 10.5
STMT_DA="print_offset THD m_stmt_da"				# 5.6, 5.7, mariadb 10.0 to 10.5

if echo $MYVER | grep -P '^(5\.7|8\.4|8\.0)' > /dev/null
then
	DA_SQL_ERRNO="print_offset Diagnostics_area m_mysql_errno"
elif echo $MYVER | grep -P '^(5\.6|10\.)' > /dev/null
then
	: place holder
elif echo $MYVER | grep -P '^(5\.5)' > /dev/null
then
	STMT_DA="print_offset THD stmt_da"
else
	STMT_DA='printf ", 0"'
	DA_STATUS='printf ", 0"'
	DA_SQL_ERRNO='printf ", 0"'
fi

LEX_COMMENT=""
VIEW_TABLES=""
if echo $MYVER | grep -P '^(8\.4|8\.0)' > /dev/null
then
	LEX_COMMENT='printf ", 0"'
	# TABLE_LIST struct was used in older versions of mysql, its replacement is Table_ref class
	# VIEW_TABLES="print_offset TABLE_LIST view_tables" 
	VIEW_TABLES="print_offset Table_ref view_tables"
else
	LEX_COMMENT="print_offset LEX comment"
	VIEW_TABLES='printf ", 0"'
fi

cat <<EOF > offsets.gdb
set logging on
set width 0
define print_offset
  printf ", %d", (size_t)&((\$arg0*)0)->\$arg1
end
printf "{\"$MYVER\",\"$MYMD5\""
print_offset THD query_id
print_offset THD $THREAD_ID
print_offset THD $SEC_CONTEXT
print_offset THD $COMMAND_MEMBER
print_offset THD lex
$LEX_COMMENT
print_offset Security_context $USER
print_offset Security_context $HOST
print_offset Security_context $IP
print_offset Security_context $PRIV_USER
print_offset THD $DB
print_offset THD killed
$CLIENT_CAPS
$CONNECT_ATTRS
print_offset THD net
$LEX_SQL
$FOUND_ROWS
$SENT_ROW_COUNT
$ROW_COUNT_FUNC
$STMT_DA
$DA_STATUS
$DA_SQL_ERRNO
$VIEW_TABLES
printf "}"
EOF

SYMPARAM=""
if [ -n "$2" ]
then
	SYMPARAM="-s $2 -e"
fi

if which gdb > /dev/null 2>&1
then
	:
else
        echo "ERROR: gdb not found. Make sure gdb is installed and on the path."
        exit 3
fi

if gdb -n -q -batch -x offsets.gdb $SYMPARAM  $1 > /dev/null 2>&1
then
	:
else
	echo "GDB failed!!!" > /dev/stderr
	exit 2
fi

OFFSETS=`cat gdb.txt`
echo "//offsets for: $1 ($FULL_MYVER)"
echo "$OFFSETS,"

# clean up
rm gdb.txt
rm offsets.gdb
