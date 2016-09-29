CPPC = g++
CPPFLAGS = -Wall -pedantic -std=c++14 -I/user/local/include
LDFLAGS = -L/usr/local/lib -lgmp

SRCS = main.cpp ElGamal.cpp
EXECUTABLE = main

debug: CPPFLAGS += -g -DDEBUG
debug: MODE = Debug
release: CPPFLAGS += -O2 -Dsecure_exponentiation -DNDEBUG
release: MODE = Release
debug release: $(EXECUTABLE)

OBJS = $(patsubst %.cpp,$(MODE)/obj/%.o,$(SRCS))

# Link program.  Library argument must come last or the linker will complain.
# (Not 100% sure why.)
executable: $(OBJS) | $(MODE)/bin/
	$(CPPC) $(OBJS) -o $(MODE)/bin/$(EXECUTABLE) $(LDFLAGS)

# Create obj directory if missing.
$(OBJS): | $(MODE)/obj/

$(MODE)/%/:
	@mkdir -p $@

# Rule for compiling source files.
%.o: %.cpp
	$(CPPC) $(CPPFLAGS) -c $< -o $@

# Delete all object files.
clean:
	$(RM) -r Debug/obj/ Release/obj/

# Delete linked program.
dist-clean:
	$(RM) -r Debug/bin/ Release/bin/