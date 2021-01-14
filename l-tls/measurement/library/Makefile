
ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -O2 -g3 -I../include -D_FILE_OFFSET_BITS=64

ifdef LD_LIBRARY_PATH
ALL_CFLAGS += -I../../papi/src/install/include -L../../papi/src/install/lib -lpapi
endif

OBJS_MEASUREMENT =	measure.o measure_wrap.o papilib.o timelib.o

.SILENT:

.PHONY: all clean

all: libmeasurement.a

libmeasurement.a: $(OBJS_MEASUREMENT)
	echo "  AR    $@"
	$(AR) src $@ $(OBJS_MEASUREMENT)

.c.o:
	echo "  gcc   $<"
	gcc $(ALL_CFLAGS) -c $<

clean:
	rm -f *.o libmeasurement.a