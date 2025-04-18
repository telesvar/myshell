CC       ?= cc
CFLAGS   ?= -std=c23 -Wall -Wextra
INCLUDES :=
LDFLAGS  :=
LIBS     ?= -lutf8proc
SRC      = myshell.c
OBJ      = $(SRC:.c=.o)
TARGET   = myshell.out

ifneq ("$(wildcard /usr/local/include)","")
    INCLUDES += -I/usr/local/include
endif

ifneq ("$(wildcard /usr/local/lib)","")
    LDFLAGS += -L/usr/local/lib
endif

INCLUDES += $(USER_INCLUDES)
LDFLAGS  += $(USER_LDFLAGS)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(INCLUDES) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f $(OBJ) $(TARGET)

.PHONY: all clean
