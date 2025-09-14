#pragma once
#include <android/log.h>
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  "sfrotate", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "sfrotate", __VA_ARGS__)

#ifdef SFROTATE_DEBUG
  #define LOGV(...) __android_log_print(ANDROID_LOG_INFO,  "sfrotate", __VA_ARGS__)
#else
  #define LOGV(...) ((void)0)
#endif