#ifndef __H_DTLS_LOGGER__
#define __H_DTLS_LOGGER__

#include <string.h>

#define DTLS_LOGGER_NO_ERROR                     0x1000
#define DTLS_LOGGER_RESOURCE_ALLOCATION_PROBLEM  DTLS_LOGGER_NO_ERROR + 0x01
#define DTLS_LOGGER_HANDLER_LIMIT_ERROR          DTLS_LOGGER_NO_ERROR + 0x02
#define DTLS_LOGGER_HANDLER_NOT_FOUND            DTLS_LOGGER_NO_ERROR + 0x03
#define DTLS_LOGGER_LOG_ATTR_ALREADY_INITIALIZED DTLS_LOGGER_NO_ERROR + 0x04

/**
 * @enum LogSeverity
 * @brief Enumeration of log severity levels.
 */
typedef enum {
  VERBOSE, /**< Detailed information */
  INFO,    /**< General information */
  DEBUG,   /**< Debugging information */
  WARN,    /**< Warning conditions */
  ERROR,   /**< Error conditions */
  CRIT,    /**< Critical conditions */
} LogSeverity;

/**
 * @struct LogAttribute
 * @brief Attributes for configuring log files.
 */
typedef struct {
  char* path;          /**< Path to the log file */
  int   max_line_size; /**< Maximum size of a log lines in file */
} LogAttribute;

/**
 * @struct LogEvent
 * @brief Structure representing a log event.
 */
typedef struct {
  long long   timestamp; /**< Timestamp of the event */
  int         line;      /**< Line number in the source code */
  char*       rlt;       /**< Relative path of the source file */
  char*       msg;       /**< Log message */
  LogSeverity severity;  /**< Severity of the log event */
} LogEvent;

/**
 * @struct LogHandler
 * @brief Structure representing a log handler.
 */
typedef struct {
  char* name; /**< Name of the handler */
  void* fnp;  /**< Function pointer to the handler */
} LogHandler;

/**
 * @struct LogEventHandler
 * @brief Structure representing an event and its handler.
 */
typedef struct {
  LogEvent*   event;   /**< Pointer to the log event */
  LogHandler* handler; /**< Log handler */
} LogEventHandler;

/**
 * @typedef dtls_log_handler
 * @brief Function pointer type for log handlers.
 */
typedef void (*dtls_log_handler)(LogEvent event);

/** */

/**
 * @def DTLS_LOGGER_BUFFER_SIZE
 * @brief Size of the formatted log buffer.
 */
#define DTLS_LOGGER_BUFFER_SIZE      1024

/**
 * @def DTLS_LOGGER_SET_MAX_HANDLERS
 * @brief Maximum number of global log handlers.
 */
#define DTLS_LOGGER_SET_MAX_HANDLERS 100

/**
 * @def TIME_FMT
 * @brief Format for date and time in logs.
 */
#define TIME_FMT                     "%d-%m-%Y %H:%M:%S"

/**
 * @def PFX_SRC_PATH
 * @brief Prefix for source path in log messages.
 */
#define PFX_SRC_PATH                 "src"

/**
 * @def LABEL
 * @brief Format for log labels.
 */
#define LABEL                        " %s:%d - "

/**
 * @def __RLT__
 * @brief Macro to get the relative path of the source file.
 */
#define __RLT__ \
  (strstr(__FILE__, PFX_SRC_PATH) ? strstr(__FILE__, PFX_SRC_PATH) : __FILE__)

/**
 * @def DEBUG
 * @brief Macro to log a debug message.
 *
 * @param message The debug message.
 * @param ... Additional arguments for the debug message.
 */
#define DEBUG(message, ...) \
  dtls_logger(message, __RLT__, __LINE__, DEBUG, ##__VA_ARGS__);

/**
 * @def INFO
 * @brief Macro to log an informational message.
 *
 * @param message The informational message.
 * @param ... Additional arguments for the informational message.
 */
#define INFO(message, ...) \
  dtls_logger(message, __RLT__, __LINE__, INFO, ##__VA_ARGS__);

/**
 * @def WARN
 * @brief Macro to log a warning message.
 *
 * @param message The warning message.
 * @param ... Additional arguments for the warning message.
 */
#define WARN(message, ...) \
  dtls_logger(message, __RLT__, __LINE__, WARN, ##__VA_ARGS__);

/**
 * @def ERROR
 * @brief Macro to log an error message.
 *
 * @param message The error message.
 * @param ... Additional arguments for the error message.
 */
#define ERROR(message, ...) \
  dtls_logger(message, __RLT__, __LINE__, ERROR, ##__VA_ARGS__);

/**
 * @def CRIT
 * @brief Macro to log a critical message.
 *
 * @param message The critical message.
 * @param ... Additional arguments for the critical message.
 */
#define CRIT(message, ...) \
  dtls_logger(message, __RLT__, __LINE__, CRIT, ##__VA_ARGS__);

/**
 * @def RAISE_STATUS
 * @brief Macro to change status to bad code and go to clean up.
 *
 * @param __status The status code to set.
 * @param message The critical message.
 * @param ... Additional arguments for the critical message.
 */
#define RAISE_STATUS(__status, message, ...)                     \
  dtls_logger(message, __RLT__, __LINE__, ERROR, ##__VA_ARGS__); \
  status = __status;                                             \
  goto clean_up

/**  */

/**
 * @brief Writes a log event to stdout or stderr based on severity.
 *
 * @param event The log event to write.
 */
static void dtls_logger_write_stdout_handler(LogEvent event)
  __attribute__((used));

/**
 * @brief Dummy function for handling log events to a file.
 *
 * @param event The log event to handle.
 */
static void dtls_logger_write_file_handler(LogEvent event)
  __attribute__((used));

/**
 * @brief Call the thread-handler function with this wrapper.
 *
 * @param vargs The `LogEventHandler` will be injected here.
 */
static void* dtls_logger_pthread_handler_fn(void* vargs) __attribute__((used));

/**
 * @brief Logs a msg with the specified severity.
 *
 * @param msg The log msg.
 * @param rlt The relative path of the source file.
 * @param line The line number in the source file.
 * @param severity The severity of the log msg.
 * @param ... Additional arguments for the log msg.
 */
void dtls_logger(char* msg, char* rlt, int line, LogSeverity severity, ...);

/**  */

/**
 * @brief Adds a log handler to the dtls_logger.
 *
 * @param name The name of the log handler.
 * @param fnp The function pointer to the log handler.
 * @return int Status code indicating the result of the operation.
 * @retval DTLS_LOGGER_NO_ERROR Success.
 * @retval DTLS_LOGGER_HANDLER_LIMIT_ERROR Maximum number of handlers
 * exceeded.
 */
extern int dtls_logger_add_log_handler(char* name, dtls_log_handler fnp);

/**
 * @brief Removes a log handler from the dtls_logger.
 *
 * @param name The name of the log handler to remove.
 * @return int Status code indicating the result of the operation.
 * @retval DTLS_LOGGER_NO_ERROR Success.
 * @retval DTLS_LOGGER_HANDLER_NOT_FOUND Handler not found.
 */
extern int dtls_logger_remove_log_handler(char* name);

/**
 * @brief Sets the log attribute for the dtls_logger.
 *
 * @param attr The log attribute to set.
 * @return int Status code indicating the result of the operation.
 * @retval DTLS_LOGGER_NO_ERROR Success.
 * @retval DTLS_LOGGER_RESOURCE_ALLOCATION_PROBLEM Resource allocation
 * problem.
 */
extern int dtls_logger_set_log_attribute(LogAttribute attr);

#endif  // __H_DTLS_LOGGER__
