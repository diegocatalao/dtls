/**
 * @file conate.c
 * @brief Time utility functions for retrieving and formatting timestamps.
 */

#include "conate.h"

#include <sys/time.h>

/**
 * @brief Retrieves the current time in seconds since the Unix Epoch (UTC).
 *
 * Provided buffer with the current timestamp in UTC.
 *
 * @param[out] obuff Pointer to a long variable where the current time (in
 * seconds) will be stored.
 *
 * @return DTLS_CONATE_NO_ERROR on success.
 * @return DTLS_CONATE_INVALID_POINTER if the provided pointer is NULL.
 * @return DTLS_CONATE_TIME_ERROR if the system call to retrieve time fails.
 */
int dtls_conate_timenow(long* obuff) {
  struct timeval tv;

  if (obuff == NULL) {
    return DTLS_CONATE_INVALID_POINTER;
  }

  if (gettimeofday(&tv, NULL) != 0) {
    return DTLS_CONATE_TIME_ERROR;
  }

  *obuff = tv.tv_sec;

  return DTLS_CONATE_NO_ERROR;
}

/**
 * @brief Formats a timestamp as a string using the local timezone.
 *
 * Converts a timestamp to a formatted string based on the specified format and
 * the local timezone.
 *
 * @param[in] tms Pointer to a long containing the timestamp to format (in
 * seconds since the Unix Epoch).
 * @param[out] obuff Pointer to a character buffer where the formatted time
 * string will be stored.
 * @param[in] size Size of the output buffer `obuff`.
 * @param[in] fmt Format string compatible with `strftime`.
 *
 * @return DTLS_CONATE_NO_ERROR on success.
 * @return DTLS_CONATE_TIME_ERROR if the formatted string length exceeds the
 * buffer size or other error.
 */
int dtls_conate_timefmt(long* tms, char* obuff, int size, const char* fmt) {
  struct tm* tm_info;
  time_t     timestamp = (time_t)(*tms);

  tm_info = localtime(&timestamp);

  if (strftime(obuff, size, fmt, tm_info) == 0) {
    return DTLS_CONATE_TIME_ERROR;
  }

  return DTLS_CONATE_NO_ERROR;
}

/**
 * @brief Formats a timestamp as a string in UTC.
 *
 * Converts a timestamp to a formatted string based on the specified format in
 * Coordinated Universal Time (UTC).
 *
 * @param[in] tms Pointer to a long containing the timestamp to format (in
 * seconds since the Unix Epoch).
 * @param[out] obuff Pointer to a character buffer where the formatted time
 * string will be stored.
 * @param[in] size Size of the output buffer `obuff`.
 * @param[in] fmt Format string compatible with `strftime`.
 *
 * @return DTLS_CONATE_NO_ERROR on success.
 * @return DTLS_CONATE_TIME_ERROR if the formatted string length exceeds the
 * buffer size or other error.
 */
int dtls_conate_timefmt_utc(long* tms, char* obuff, int size, const char* fmt) {
  struct tm* tm_info;
  time_t     timestamp = (time_t)(*tms);

  tm_info = gmtime(&timestamp);

  if (strftime(obuff, size, fmt, tm_info) == 0) {
    return DTLS_CONATE_TIME_ERROR;
  }

  return DTLS_CONATE_NO_ERROR;
}
