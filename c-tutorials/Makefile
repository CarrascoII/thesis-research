LOCAL_CFLAGS = -Wall -W -Wdeclaration-after-statement -D_FILE_OFFSET_BITS=64

.PHONY: all pointers_obj pointers shape_obj shape person_obj person all clean

all: pointers_obj shape_obj person_obj

pointers_obj:
	$(CC) $(LOCAL_CFLAGS) pointers.c -o pointers.out

pointers: pointers_obj
	./pointers.out

shape_obj:
	$(CC) $(LOCAL_CFLAGS) shape.c -o shape.out

shape: shape_obj
	./shape.out

person_obj:
	$(CC) $(LOCAL_CFLAGS) person.c -o person.out

person: person_obj
	./person.out

all: pointers shape person

clean:
	rm -f pointers.out
	rm -f shape.out
	rm -f person.out