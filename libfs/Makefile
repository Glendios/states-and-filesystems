lib := libfs.a
objs := fs.o disk.o
CFLAGS := -Wall -Wextra -Werror -MMD

# Don't print the commands unless explicitly requested with `make V=1`
ifneq ($(V),1)
Q := @
V := 0
endif

# Current directory
CUR_PWD := $(shell pwd)

# Define compilation toolchain
CC	= gcc

all: $(lib)

# Include dependencies
deps := $(patsubset %.o,%.d,$(objs))
-include $(deps)

# Rule for lib
$(lib): $(objs)
	@echo "ar rcs $@"
	$(Q)ar rcs $@ $^

# Generic rule for compiling objects
%.o: %.c
	@echo "CC $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

# Cleaning rule
clean:
	@echo "CLEAN	$(CUR_PWD)"
	$(Q)rm -f $(lib) $(objs) $(deps)