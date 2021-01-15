
ALL_CFLAGS = -Wall -W -Wdeclaration-after-statement -O2 -g3 -I../include -D_FILE_OFFSET_BITS=64
PAPI_CFLAGS ?=

OBJS_MEASUREMENT =	measure.o measure_wrap.o papilib.o timelib.o

.SILENT:

.PHONY: all print clean

all: print libmeasurement.a

print:
	echo "make measurement:"

libmeasurement.a: $(OBJS_MEASUREMENT)
	echo "  AR    $@"
	$(AR) src $@ $(OBJS_MEASUREMENT)

.c.o:
	echo "  gcc   $<"
	gcc $(ALL_CFLAGS) $(PAPI_CFLAGS) -c $<

clean:
	echo -n "Cleaning measurement..... "
	rm -f *.o libmeasurement.a
	echo "ok"