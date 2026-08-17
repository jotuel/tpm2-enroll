CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -fPIC -pthread
LDFLAGS ?= -shared
PKG_CFLAGS := $(shell pkg-config --cflags tss2-esys tss2-mu tss2-rc gio-2.0 glib-2.0 pam 2>/dev/null || echo "-I/usr/include/tss2 -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/include/sysprof-6")
PKG_LIBS   := $(shell pkg-config --libs tss2-esys tss2-mu tss2-rc gio-2.0 glib-2.0 pam 2>/dev/null || echo "-ltss2-esys -ltss2-mu -ltss2-rc -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lpam")

ALL_CFLAGS := $(CFLAGS) $(PKG_CFLAGS) -Isrc

LIB_TARGET := pam_bio_tpm2.so
CLI_TARGET := tpm2-enroll
CLI_UNENROLL := tpm2-unenroll

COMMON_OBJS := build/tpm2_util.o build/fprint_util.o
LIB_OBJS    := build/pam_bio_tpm2.o $(COMMON_OBJS)
CLI_OBJS    := build/tpm2_enroll.o build/tpm2_util.o build/fprint_util.o

PAM_DIR ?= /lib/security
BIN_DIR ?= /usr/local/bin

.PHONY: all clean install uninstall test

all: build/ $(LIB_TARGET) $(CLI_TARGET) $(CLI_UNENROLL)

build/:
	mkdir -p build/

build/%.o: src/%.c
	$(CC) $(ALL_CFLAGS) -c $< -o $@

$(LIB_TARGET): $(LIB_OBJS)
	$(CC) $(LDFLAGS) -o $@ $(LIB_OBJS) $(PKG_LIBS)

$(CLI_TARGET): $(CLI_OBJS)
	$(CC) $(ALL_CFLAGS) -o $@ $(CLI_OBJS) $(PKG_LIBS)
$(CLI_UNENROLL): $(CLI_TARGET)
	ln -sf $(CLI_TARGET) $(CLI_UNENROLL)


install: all
	install -d $(DESTDIR)$(PAM_DIR)
	install -m 0755 $(LIB_TARGET) $(DESTDIR)$(PAM_DIR)/$(LIB_TARGET)
	install -d $(DESTDIR)$(BIN_DIR)
	install -m 0755 $(CLI_TARGET) $(DESTDIR)$(BIN_DIR)/$(CLI_TARGET)
	ln -sf $(CLI_TARGET) $(DESTDIR)$(BIN_DIR)/$(CLI_UNENROLL)
	ln -sf $(CLI_TARGET) $(DESTDIR)$(BIN_DIR)/pam-bio-tpm2-enroll
	ln -sf $(CLI_TARGET) $(DESTDIR)$(BIN_DIR)/pam-bio-tpm2-unenroll

uninstall:
	rm -f $(DESTDIR)$(PAM_DIR)/$(LIB_TARGET)
	rm -f $(DESTDIR)$(BIN_DIR)/$(CLI_TARGET)
	rm -f $(DESTDIR)$(BIN_DIR)/$(CLI_UNENROLL)
	rm -f $(DESTDIR)$(BIN_DIR)/pam-bio-tpm2-enroll
	rm -f $(DESTDIR)$(BIN_DIR)/pam-bio-tpm2-unenroll

clean:
	rm -rf build $(LIB_TARGET) $(CLI_TARGET) $(CLI_UNENROLL)
