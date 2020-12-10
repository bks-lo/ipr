CC = gcc
CFLAG = -g -Wall -O3
DBG_CFLAG = -g -Wall -O0 -fprofile-arcs -ftest-coverage -fPIC
CINCLUDE = -I./
CLIB =
CFLAGS = $(CFLAG) $(CINCLUDE) $(CLIB)
DBG_CFLAGS = $(DBG_CFLAG) $(CINCLUDE) $(CLIB) -lcheck
SRC = $(wildcard *.c)
HEAD = $(wildcard *.h)
TAGS = ipr.so
TAGS_TEST_IPR = test_ipr

.PHONY:all
all:$(TAGS)

$(TAGS): $(SRC) $(HEAD) Makefile
	$(CC)  -shared -fPIC $(CFLAGS) -o $(TAGS) $(SRC)

test_ipr: $(SRC) $(HEAD) Makefile
	$(CC) $(DBG_CFLAGS) -DUNIT_TEST_IPR -o $(TAGS_TEST_IPR) $(SRC)
	./$(TAGS_TEST_IPR)

clean:
	rm -f *.o *.gcda *.gcno *.html $(TAGS) $(TAGS_TEST_IPR)
	
install:
	cp $(TAGS) /usr/lib

