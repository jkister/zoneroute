LIB     = libnss_zoneroute.so.2
CFLAGS  = -O2 -Wall -Wextra -fPIC
LDFLAGS = -shared -Wl,-soname,$(LIB) -Wl,-z,defs
LDLIBS  = -lresolv
LIBDIR  = /usr/local/lib

$(LIB): nss_zoneroute.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

install: $(LIB)
	install -o root -g root -m 0644 $(LIB) $(LIBDIR)/$(LIB)
	ldconfig

clean:
	rm -f $(LIB)

.PHONY: install clean
