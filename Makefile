CPPC = g++
CPPFLAGS = -Wall -pedantic -std=c++14 -I/user/local/include -Iinclude
LDFLAGS = -L/usr/local/lib -lgmp

SRCS = $(shell find src -type f -name '*.cpp')
OBJS = $(patsubst src/%.cpp,obj/%.o,$(SRCS))
EXECUTABLE = main

debug: CPPFLAGS += -g -DDEBUG
release: CPPFLAGS += -O2 -Dsecure_exponentiation -DNDEBUG
debug release: bin/$(EXECUTABLE)

# Link program.  Library argument must come last or the linker will complain.
# (Not 100% sure why.)
bin/$(EXECUTABLE): $(OBJS)
	@mkdir -p $(@D)
	$(CPPC) $(OBJS) -o $@ $(LDFLAGS)

# Rule for compiling source files.
obj/%.o : src/%.cpp
	@mkdir -p $(@D)
	$(CPPC) $(CPPFLAGS) -c $< -o $@

# Delete all object and binary files.
clean:
	$(RM) -r bin obj