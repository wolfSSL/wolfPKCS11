CC ?= gcc
AR ?= ar
CFLAGS ?= -O2 -g
CFLAGS += -Wall -Wextra -Wno-unused-parameter -fPIC
LDFLAGS ?=
LDLIBS ?=
LDLIBS += -ldl -lpthread -lm
WOLFSSL_DIR ?= ../../wolfssl
WOLFPKCS11_DIR ?= ../..

BUILD_DIR := build

COMMON_CPPFLAGS := -DWOLFSSL_USER_SETTINGS -I. -I.. \
    -I$(WOLFSSL_DIR) -I$(WOLFSSL_DIR)/wolfssl -I$(WOLFSSL_DIR)/wolfssl/wolfcrypt \
    -I$(WOLFPKCS11_DIR) -I$(WOLFPKCS11_DIR)/wolfpkcs11 -I$(WOLFPKCS11_DIR)/src
WOLFCRYPT_CPPFLAGS := $(COMMON_CPPFLAGS) -DWOLFSSL_LIB
ENGINE_CPPFLAGS := $(COMMON_CPPFLAGS) -DBUILDING_WOLFPKCS11 -DDEBUG_WOLFPKCS11
TEST_CPPFLAGS := $(COMMON_CPPFLAGS)

WOLFCRYPT_SRCS := \
    $(WOLFSSL_DIR)/wolfcrypt/src/aes.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/asn.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/coding.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/cryptocb.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/des3.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/dsa.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/dh.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/ecc.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/ecc_fp.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/error.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hash.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/md5.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/hmac.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/integer.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/logging.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/memory.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/random.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/rsa.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha256.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha512.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sha3.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/signature.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/pwdbased.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_int.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/sp_c32.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_encrypt.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_pkcs11.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wc_port.c \
    $(WOLFSSL_DIR)/wolfcrypt/src/wolfmath.c

ENGINE_SRCS := \
    $(WOLFPKCS11_DIR)/src/internal.c \
    $(WOLFPKCS11_DIR)/src/wolfpkcs11.c \
    $(WOLFPKCS11_DIR)/src/slot.c \
    $(WOLFPKCS11_DIR)/src/crypto.c

TEST_SRCS := pkcs11_interop.c

WOLFCRYPT_OBJS := $(patsubst $(WOLFSSL_DIR)/%.c,$(BUILD_DIR)/wolfssl/%.o,$(WOLFCRYPT_SRCS))
ENGINE_OBJS := $(patsubst  $(WOLFPKCS11_DIR)/%.c,$(BUILD_DIR)/wolfpkcs11/%.o,$(ENGINE_SRCS))
TEST_OBJS := $(patsubst %.c,$(BUILD_DIR)/interop-test/%.o,$(TEST_SRCS))

all: test

interop: $(BUILD_DIR)/pkcs11_interop

$(BUILD_DIR)/wolfssl/%.o: $(WOLFSSL_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(WOLFCRYPT_CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/wolfpkcs11/%.o: $(WOLFPKCS11_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(ENGINE_CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/interop-test/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(TEST_CPPFLAGS) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/libwolfcrypt-interop.so: $(WOLFCRYPT_OBJS)
	@mkdir -p $(dir $@)
	$(CC) -shared -o $@ $(WOLFCRYPT_OBJS) $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/libwolfpkcs11-interop.so: $(ENGINE_OBJS) $(BUILD_DIR)/libwolfcrypt-interop.so
	@mkdir -p $(dir $@)
	$(CC) -shared -o $@ $(ENGINE_OBJS) -L$(BUILD_DIR) -lwolfcrypt-interop $(LDFLAGS) $(LDLIBS)

$(BUILD_DIR)/pkcs11_interop: $(TEST_OBJS) $(BUILD_DIR)/libwolfpkcs11-interop.so $(BUILD_DIR)/libwolfcrypt-interop.so
	$(CC) -o $@ $(TEST_OBJS) -L$(BUILD_DIR) -lwolfpkcs11-interop -lwolfcrypt-interop $(LDFLAGS) $(LDLIBS)

.PHONY: test
test: $(BUILD_DIR)/pkcs11_interop
	WOLFPKCS11_MODULE=$(BUILD_DIR)/libwolfpkcs11-interop.so LD_LIBRARY_PATH=$(BUILD_DIR) $(BUILD_DIR)/pkcs11_interop
debug: $(BUILD_DIR)/pkcs11_interop
	WOLFPKCS11_MODULE=$(BUILD_DIR)/libwolfpkcs11-interop.so LD_LIBRARY_PATH=$(BUILD_DIR) gdb $(BUILD_DIR)/pkcs11_interop

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)/wolfssl $(BUILD_DIR)/wolfPKCS11 $(BUILD_DIR)/interop-test \
		$(BUILD_DIR)/libwolfcrypt-interop.so $(BUILD_DIR)/libwolfpkcs11-interop.so \
		$(BUILD_DIR)/pkcs11_interop
	rm -rf token-store
	@# Safely remove build directory, if local
	rm -rf ./build
