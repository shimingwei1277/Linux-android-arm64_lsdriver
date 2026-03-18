LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tcp_server
LOCAL_SRC_FILES := src/main.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CPPFLAGS := -std=c++2c -Wall -Wextra
LOCAL_LDLIBS := -llog
include $(BUILD_EXECUTABLE)

# ------------------------------------------------------------------
# 编译完成后自动推送到设备，不自动运行
AKERNEL_MODULE := tcp_server
AKERNEL_PUSH_DIR := /data/akernel
AKERNEL_TEMP_FILE := /data/local/tmp/$(AKERNEL_MODULE)
AKERNEL_REMOTE_FILE := $(AKERNEL_PUSH_DIR)/$(AKERNEL_MODULE)
AKERNEL_BINARY := $(NDK_APP_LIBS_OUT)/$(TARGET_ARCH_ABI)/$(AKERNEL_MODULE)

.PHONY: push-akernel

push-akernel: $(AKERNEL_BINARY)
	@echo [AKERNEL] push $(AKERNEL_BINARY) to $(AKERNEL_REMOTE_FILE)
	@adb push "$(call host-path,$(AKERNEL_BINARY))" "$(AKERNEL_TEMP_FILE)"
	@adb shell "su -c 'mkdir -p $(AKERNEL_PUSH_DIR) && mv -f $(AKERNEL_TEMP_FILE) $(AKERNEL_REMOTE_FILE) && chmod 755 $(AKERNEL_REMOTE_FILE)'"

all: push-akernel
