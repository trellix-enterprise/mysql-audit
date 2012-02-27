noinst_LTLIBRARIES = libudis86.la

#include_ladir = ${includedir}
#libudis86_ladir = ${includedir}/libudis86

libudis86_la_SOURCES =	itab.c \
			input.c \
			decode.c \
			syn.c \
			syn-intel.c \
			syn-att.c \
			udis86.c \
			input.h \
			syn.h \
			decode.h \
			extern.h \
			types.h \
			itab.h \
			opgen.py



itab.c itab.h: ../docs/x86optable.xml opgen.py
	python ./opgen.py
