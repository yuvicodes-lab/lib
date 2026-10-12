LOCAL_PATH := $(call my-dir)

# Dobby Static Library
include $(CLEAR_VARS)
LOCAL_MODULE := dobby
LOCAL_SRC_FILES := Dobby/libdobby.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/Dobby
include $(PREBUILT_STATIC_LIBRARY)

# CrackLib — curl-only URL hook (no strlen, no patch)
include $(CLEAR_VARS)

LOCAL_MODULE := CrackLib
LOCAL_SRC_FILES := hook.cpp jnihook.cpp config.cpp

LOCAL_STATIC_LIBRARIES := dobby

# Production flags
LOCAL_CPPFLAGS := -std=c++17 -O2 -fvisibility=hidden -fno-rtti -D_DEBUG
LOCAL_CFLAGS := -O2 -fvisibility=hidden -fno-exceptions

LOCAL_LDLIBS := -llog -ldl

# Remove debug symbols for production
LOCAL_STRIP_MODULE := true

include $(BUILD_SHARED_LIBRARY)
