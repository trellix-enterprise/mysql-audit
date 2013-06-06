#!/bin/sh

if [ $# = 0 ]; then 	
	echo "Usage: $0 <mysqld executable> [optional mysqld symbols]"
	echo "Will extract offsets from mysqld. Requires gdb, md5sum and mysqld symbols."
	exit 1
fi

#extract the version of mysqld

FULL_MYVER=`$1 --version | grep -P  -o 'Ver\s+[\w\.-]+'| awk '{print $2}'`

#extract the md5 digest

MYMD5=`md5sum -b $1 | awk -v Field=1 '{print $1}'`

MYVER="$FULL_MYVER"
echo $FULL_MYVER | grep  'log' > /dev/null


if [ $? = 0 ]; then
	MYVER=`echo "$MYVER" | grep -P  -o '.+(?=-log)'`
fi

COMMAND_MEMBER=command

#in 5.6 command member is named m_command
echo $MYVER | grep -P '^5.6' > /dev/null
if [ $? = 0 ]; then
	COMMAND_MEMBER=m_command
fi

echo "set logging on" > offsets.gdb
echo 'printf "{\"'$MYVER'\",\"'$MYMD5'\", %d, %d, %d, %d, %d, %d}", ((size_t)&((THD *)log_slow_statement)->query_id) - (size_t)log_slow_statement, ((size_t)&((THD *)log_slow_statement)->thread_id) - (size_t)log_slow_statement, ((size_t)&((THD *)log_slow_statement)->main_security_ctx) - (size_t)log_slow_statement, ((size_t)&((THD *)log_slow_statement)->'$COMMAND_MEMBER') - (size_t)log_slow_statement, ((size_t)&((THD *)log_slow_statement)->lex) - (size_t)log_slow_statement, (size_t)&((LEX*)log_slow_statement)->comment - (size_t)  log_slow_statement' >> offsets.gdb

SYMPARAM=""
if [ -n "$2" ]; then
	SYMPARAM="-s $2 -e"
fi

gdb -n -q -batch -x offsets.gdb $SYMPARAM  $1 > /dev/null 2>&1

if [ $? != 0 ]; then
	echo "GDB failed!!!" > /dev/stderr
	exit 2
fi

OFFSETS=`cat gdb.txt`
echo "//offsets for: $1 ($FULL_MYVER)"
echo "$OFFSETS,"

#clean up
rm gdb.txt
rm offsets.gdb

