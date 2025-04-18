/*
 * termline.h provides a simple, robust, Unicode-aware terminal line editing library.
 *
 * Features:
 *   - Full Unicode support via utf8proc
 *   - Core Emacs-style keyboard shortcuts (arrow keys, basic editing)
 *   - History management with optional persistence
 *   - Tab completion support
 *
 * Version: 0.1.0
 *
 * To use this library, do this in *one* C/C++ file:
 *   #define TERMLINE_IMPLEMENTATION
 *   #include "termline.h"
 *
 * Dependencies:
 *   - utf8proc <https://github.com/JuliaStrings/utf8proc>
 *
 * Copyright 2025 Dair Aidarkhanov
 * SPDX-License-Identifier: 0BSD
 */

#ifndef TERMLINE_H
#define TERMLINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * Result Codes and Status Types
 */

/* TermlineResult defines main error codes. */
typedef enum {
  TERMLINE_OK             =  0, /* Operation succeeded */
  TERMLINE_ERROR_MEMORY   = -1, /* Memory allocation failed */
  TERMLINE_ERROR_INPUT    = -2, /* I/O operation failed */
  TERMLINE_ERROR_TERMINAL = -3, /* Terminal control operation failed */
  TERMLINE_ERROR_OVERFLOW = -4, /* Buffer capacity exceeded */
  TERMLINE_ERROR_INVALID  = -5  /* Invalid argument or state */
} TermlineResult;

/* TermlineKeyStatus defines key handling status codes. */
typedef enum {
  TERMLINE_KEY_HANDLED  = 0, /* Key was processed normally */
  TERMLINE_KEY_COMPLETE = 1, /* Line editing completed (Enter pressed) */
  TERMLINE_KEY_CANCEL   = 2, /* Line editing canceled (Ctrl-C pressed) */
  TERMLINE_KEY_EOF      = 3  /* End of file (Ctrl-D on empty line) */
} TermlineKeyStatus;

/*
 * Core Data Types
 */

/* TermlineContext is an opaque handle for thread-safe operations. */
typedef struct TermlineContext TermlineContext;

/* TermlineCompletionCallback generates completion suggestions for the current input. */
typedef char **(*TermlineCompletionCallback)(
  const char *text, int start, int end, void *userdata);

/* TermlineHistory manages line history with configurable behavior. */
typedef struct {
  char **lines;    /* Array of history lines (owned by the history) */
  int length;      /* Current number of history entries */
  int capacity;    /* Maximum number of history entries */
  bool allow_dups; /* Whether duplicate entries are allowed */
} TermlineHistory;

/*
 * Public API Functions
 */

/* termline_context_create creates a new context for thread-safe operations. */
TermlineContext *termline_context_create(void);

/* termline_context_destroy frees all resources associated with a context. */
void termline_context_destroy(TermlineContext *ctx);

/* termline_readline reads a line from stdin with the given prompt. */
char *termline_readline(const char *prompt);

/* termline_readline_ctx reads a line using the specified context. */
char *termline_readline_ctx(TermlineContext *ctx, const char *prompt);

/* termline_readline_fd reads a line from custom file descriptors. */
char *termline_readline_fd(const char *prompt, int in_fd, int out_fd);

/* termline_readline_fd_ctx reads a line with custom fd and context. */
char *termline_readline_fd_ctx(TermlineContext *ctx,
                               const char *prompt,
                               int in_fd,
                               int out_fd);

/* termline_free safely frees memory allocated by any termline function. */
void termline_free(void *ptr);

/* termline_history_create creates a new history with specified capacity. */
TermlineHistory *termline_history_create(int max_capacity);

/* termline_history_destroy frees all resources associated with history. */
void termline_history_destroy(TermlineHistory *history);

/* termline_history_set_ctx attaches history to the specified context. */
void termline_history_set_ctx(TermlineContext *ctx, TermlineHistory *history);

/* termline_history_add adds a line to history, returns 1 if added, 0 if duplicate. */
int termline_history_add(TermlineHistory *history, const char *line);

/* termline_history_save writes history to a file, returns 0 on success. */
int termline_history_save(TermlineHistory *history, const char *filename);

/* termline_history_load reads history from a file, returns 0 on success. */
int termline_history_load(TermlineHistory *history, const char *filename);

/* termline_history_allow_duplicates configures whether duplicates are allowed. */
void termline_history_allow_duplicates(TermlineHistory *history, bool allow);

/* termline_set_completion_callback sets the tab completion handler. */
void termline_set_completion_callback(TermlineContext *ctx,
                                      TermlineCompletionCallback callback,
                                      void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* TERMLINE_H */

/*
 * Implementation
 */

#ifdef TERMLINE_IMPLEMENTATION

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <termios.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <sys/select.h>
#include <sys/time.h>
#include <utf8proc.h>

/*
 * Internal Constants and Macros
 */

/* TL_CTRL converts an ASCII letter to its control character code */
#define TL_CTRL(c) ((c) & 0x1F)

/* Key codes for editing operations */
#define TL_KEY_NULL       0  /* Null byte */
#define TL_KEY_CTRL_A     1  /* Move to start of line */
#define TL_KEY_CTRL_B     2  /* Move cursor left */
#define TL_KEY_CTRL_C     3  /* Cancel line editing */
#define TL_KEY_CTRL_D     4  /* Delete character or signal EOF */
#define TL_KEY_CTRL_E     5  /* Move to end of line */
#define TL_KEY_CTRL_F     6  /* Move cursor right */
#define TL_KEY_CTRL_H     8  /* Backspace */
#define TL_KEY_TAB        9  /* Tab completion */
#define TL_KEY_CTRL_J    10  /* Line feed (alternate Enter) */
#define TL_KEY_CTRL_K    11  /* Delete to end of line */
#define TL_KEY_CTRL_L    12  /* Clear screen */
#define TL_KEY_ENTER     13  /* Carriage return (Enter) */
#define TL_KEY_CTRL_N    14  /* Next history entry */
#define TL_KEY_CTRL_P    16  /* Previous history entry */
#define TL_KEY_CTRL_T    20  /* Transpose characters */
#define TL_KEY_CTRL_U    21  /* Delete entire line */
#define TL_KEY_CTRL_W    23  /* Delete word backward */
#define TL_KEY_ESC       27  /* Escape (for multi-byte sequences) */
#define TL_KEY_BACKSPACE 127 /* Backspace */

/* Buffer sizing constants */
#define TL_INITIAL_BUFFER_SIZE 256 /* Initial text buffer capacity */
#define TL_KEY_SEQUENCE_MAX    16  /* Maximum escape sequence length */
#define TL_KEY_TIMEOUT_MS      50  /* Escape sequence timeout in ms */

/* Terminal dimensions fallbacks */
#define TL_DEFAULT_COLS 80 /* Default terminal width */
#define TL_DEFAULT_ROWS 24 /* Default terminal height */

/*
 * Internal Data Structures
 */

/* UnicodeState tracks stateful grapheme breaking. */
typedef struct {
  utf8proc_int32_t grapheme_state; /* Current grapheme breaking state */
  bool initialized;                /* Whether state is initialized */
} UnicodeState;

/* TextBuffer manages UTF-8 text with grapheme awareness. */
typedef struct {
  char *data;   /* UTF-8 text content (owned) */
  int length;   /* Length in bytes */
  int capacity; /* Buffer capacity in bytes */

  int *grapheme_offsets; /* Byte offsets of grapheme boundaries (owned) */
  int grapheme_count;    /* Number of grapheme clusters */
  int grapheme_capacity; /* Capacity of grapheme_offsets array */

  bool graphemes_valid; /* Whether grapheme data is current */
} TextBuffer;

/* EditorState tracks cursor position in grapheme and byte units. */
typedef struct {
  int position;      /* Cursor position in grapheme units */
  int byte_position; /* Cursor position in bytes */
} EditorState;

/* DisplayState tracks terminal dimensions and rendering metrics. */
typedef struct {
  int width;        /* Terminal width in columns */
  int height;       /* Terminal height in rows */
  int prompt_width; /* Visual width of prompt in columns */
} DisplayState;

/* TerminalState manages terminal settings and I/O. */
typedef struct {
  struct termios original;              /* Original terminal settings to restore */
  int in_fd;                            /* Input file descriptor */
  int out_fd;                           /* Output file descriptor */
  bool term_mode_set;                   /* Whether terminal is in raw mode */
  volatile sig_atomic_t winch_received; /* SIGWINCH received flag */
} TerminalState;

/* HistoryState manages history navigation state. */
typedef struct {
  TermlineHistory *history; /* History data (not owned) */
  int index;                /* Current position in history */
  char *saved_line;         /* Current line saved during history navigation */
} HistoryState;

/* CompletionState manages tab completion state. */
typedef struct {
  TermlineCompletionCallback completion_func; /* Completion callback */
  void *completion_data;                      /* User data for callback */
  char **completions;                         /* Array of completions (owned) */
  int completion_count;                       /* Number of completions */
  int completion_index;                       /* Current completion index */
} CompletionState;

/* TermlineState manages the full line editing session. */
typedef struct {
  TextBuffer buffer;          /* Text buffer with grapheme awareness */
  EditorState editor;         /* Cursor and editing state */
  UnicodeState unicode;       /* Unicode handling state */
  DisplayState display;       /* Display rendering state */
  TerminalState terminal;     /* Terminal I/O state */
  HistoryState history;       /* History navigation state */
  CompletionState completion; /* Completion state */

  const char *prompt; /* Current prompt (not owned) */
  int prompt_len;     /* Length of prompt in bytes */

  struct TermlineContext *ctx; /* Parent context (not owned) */
} TermlineState;

/* TermlineContext holds global state for the library. */
struct TermlineContext {
  TermlineHistory *history; /* Global history (owned) */
  TermlineState *state;     /* Current session state (owned) */

  /* Global callbacks */
  TermlineCompletionCallback completion_func;
  void *completion_data;
};

/*
 * Function Declarations
 */

/* Unicode text analysis */
static inline int tl_utf8_prev_pos(const char *str, int pos);
static inline int tl_next_codepoint(const char *str, int len, int pos, int *codepoint);
static inline int tl_prev_codepoint(const char *str, int pos, int *codepoint);
static inline int tl_next_grapheme_boundary(const char *str, int len, int pos, UnicodeState *state);
static inline int tl_prev_grapheme_boundary(const char *str, int len, int pos, UnicodeState *state);
static inline int tl_grapheme_to_byte_offset(const TextBuffer *buffer, int grapheme_pos);
static inline int tl_byte_to_grapheme_offset(const TextBuffer *buffer, int byte_pos);
static inline bool tl_is_word_char(int codepoint);
static inline int tl_next_word_boundary(const char *str, int len, int pos);
static inline int tl_prev_word_boundary(const char *str, int pos);
static inline int tl_calculate_width(const char *str, int len);
static void tl_update_grapheme_boundaries(TextBuffer *buffer);

/* Text buffer operations */
static int tl_buffer_init(TextBuffer *buffer, int initial_size);
static void tl_buffer_free(TextBuffer *buffer);
static int tl_buffer_ensure_capacity(TextBuffer *buffer, int capacity);
static int tl_buffer_insert(TextBuffer *buffer, int pos, const char *text, int len);
static int tl_buffer_delete(TextBuffer *buffer, int start, int end);
static int tl_buffer_clear(TextBuffer *buffer);
static int tl_buffer_append(TextBuffer *buffer, const char *text, int len);
static int tl_buffer_append_str(TextBuffer *buffer, const char *text);
static char *tl_buffer_to_string(const TextBuffer *buffer);

/* Terminal I/O */
static int tl_write(int fd, const char *buf, size_t len);
static int tl_read_byte(int fd);
static int tl_read_byte_timeout(int fd, int timeout_ms);
static int tl_get_terminal_size(int fd, int *width, int *height);
static int tl_set_terminal_mode(TermlineState *ts);
static void tl_restore_terminal_mode(TermlineState *ts);
static void tl_handle_window_resize(TermlineState *ts);
static void tl_setup_signal_handlers(TermlineState *ts);
static void tl_reset_signal_handlers(void);
static void tl_clear_screen(int fd);

/* Editor operations */
static int tl_editor_insert_text(TermlineState *ts, const char *text, int len);
static int tl_editor_delete_char(TermlineState *ts);
static int tl_editor_backspace(TermlineState *ts);
static int tl_editor_delete_word(TermlineState *ts);
static int tl_editor_delete_to_end(TermlineState *ts);
static int tl_editor_delete_line(TermlineState *ts);
static int tl_editor_move_left(TermlineState *ts);
static int tl_editor_move_right(TermlineState *ts);
static int tl_editor_move_to_start(TermlineState *ts);
static int tl_editor_move_to_end(TermlineState *ts);
static int tl_editor_move_prev_word(TermlineState *ts);
static int tl_editor_move_next_word(TermlineState *ts);
static int tl_editor_transpose_chars(TermlineState *ts);

/* History operations */
static int tl_history_prev(TermlineState *ts);
static int tl_history_next(TermlineState *ts);
static int tl_history_add_line(TermlineState *ts);

/* Display functions */
static void tl_refresh_line(TermlineState *ts);

/* Key handling */
static int tl_handle_key(TermlineState *ts, int key);

/* Completion handling */
static int tl_update_completions(TermlineState *ts);
static void tl_free_completions(TermlineState *ts);
static int tl_complete_next(TermlineState *ts);

/* State initialization/cleanup */
static TermlineState *tl_create_state(TermlineContext *ctx, const char *prompt, int in_fd, int out_fd);
static void tl_free_state(TermlineState *ts);
static int tl_process_input(TermlineState *ts);

/*
 * Unicode Text Analysis Functions
 */

/* tl_utf8_prev_pos finds the previous UTF-8 character boundary. */
static inline int tl_utf8_prev_pos(const char *str, int pos) {
  if (!str || pos <= 0) return 0;

  /* Search backward until finding a non-continuation byte */
  int i = pos - 1;
  while (i > 0 && ((unsigned char)str[i] & 0xC0) == 0x80) {
    i--;
  }

  return i;
}

/* tl_next_codepoint decodes the next Unicode codepoint at position. */
static inline int tl_next_codepoint(const char *str, int len, int pos, int *codepoint) {
  if (!str || !codepoint || pos >= len) {
    if (codepoint) *codepoint = -1;
    return pos;
  }

  utf8proc_int32_t cp;
  utf8proc_ssize_t bytes = utf8proc_iterate(
    (const utf8proc_uint8_t *)(str + pos),
    len - pos,
    &cp
  );

  if (bytes <= 0) {
    /* Handle invalid UTF-8 */
    *codepoint = -1;
    return pos + 1;
  }

  *codepoint = cp;
  return pos + bytes;
}

/* tl_prev_codepoint decodes the Unicode codepoint before position. */
static inline int tl_prev_codepoint(const char *str, int pos, int *codepoint) {
  if (!str || !codepoint || pos <= 0) {
    if (codepoint) *codepoint = -1;
    return 0;
  }

  /* Find previous UTF-8 boundary */
  int prev_pos = tl_utf8_prev_pos(str, pos);

  /* Decode the codepoint */
  int cp;
  int next_pos = tl_next_codepoint(str, pos, prev_pos, &cp);

  /* Verify the decoded sequence */
  if (next_pos != pos || cp < 0) {
    *codepoint = -1;
    return prev_pos;
  }

  *codepoint = cp;
  return prev_pos;
}

/* tl_next_grapheme_boundary finds the next grapheme cluster boundary. */
static inline int tl_next_grapheme_boundary(const char *str, int len, int pos, UnicodeState *state) {
  if (!str || pos >= len) return len;

  /* Initialize state if needed */
  UnicodeState local_state = {0};
  if (!state) {
    local_state.initialized = true;
    local_state.grapheme_state = 0;
    state = &local_state;
  } else if (!state->initialized) {
    state->initialized = true;
    state->grapheme_state = 0;
  }

  /* Get current codepoint */
  utf8proc_int32_t cp1;
  utf8proc_ssize_t bytes1 = utf8proc_iterate(
    (const utf8proc_uint8_t*)(str + pos),
    len - pos,
    &cp1
  );

  if (bytes1 <= 0) return pos + 1; /* Invalid UTF-8 */

  int next_pos = pos + bytes1;
  if (next_pos >= len) return len;

  /* Get next codepoint */
  utf8proc_int32_t cp2;
  utf8proc_ssize_t bytes2 = utf8proc_iterate(
    (const utf8proc_uint8_t*)(str + next_pos),
    len - next_pos,
    &cp2
  );

  if (bytes2 <= 0) return next_pos + 1; /* Invalid UTF-8 */

  /* Check if there's a grapheme break between them */
  if (utf8proc_grapheme_break_stateful(cp1, cp2, &state->grapheme_state)) {
    return next_pos;
  }

  /* No break, continue to next codepoint */
  return tl_next_grapheme_boundary(str, len, next_pos, state);
}

/* tl_prev_grapheme_boundary finds the previous grapheme cluster boundary. */
static inline int tl_prev_grapheme_boundary(const char *str, int len, int pos, UnicodeState *state) {
  if (!str || pos <= 0) return 0;

  /* First back up to a valid UTF-8 boundary */
  int curr_pos = pos;
  while (curr_pos > 0 && ((unsigned char)str[curr_pos] & 0xC0) == 0x80) {
    curr_pos--;
  }

  /* If at start, return 0 */
  if (curr_pos <= 0) return 0;

  /* Initialize state if needed */
  UnicodeState local_state = {0};
  if (!state) {
    local_state.initialized = true;
    local_state.grapheme_state = 0;
    state = &local_state;
  } else if (!state->initialized) {
    state->initialized = true;
    state->grapheme_state = 0;
  }

  /* Find previous start by scanning backward */
  int prev_pos = curr_pos - 1;
  while (prev_pos > 0 && ((unsigned char)str[prev_pos] & 0xC0) == 0x80) {
    prev_pos--;
  }

  /* Check if this is a grapheme boundary by scanning forward */
  int test_pos = prev_pos;
  while (test_pos < curr_pos) {
    int next = tl_next_grapheme_boundary(str, len, test_pos, state);
    if (next >= curr_pos) {
      return prev_pos;
    }
    if (next <= test_pos) break; /* Prevent infinite loop */
    test_pos = next;
  }

  /* Not found, look further back */
  return tl_prev_grapheme_boundary(str, len, prev_pos, state);
}

/* tl_grapheme_to_byte_offset converts grapheme position to byte position. */
static inline int tl_grapheme_to_byte_offset(const TextBuffer *buffer, int grapheme_pos) {
  if (!buffer || !buffer->data) return 0;

  /* Handle case when grapheme boundaries aren't computed */
  if (!buffer->graphemes_valid || !buffer->grapheme_offsets) {
    /* Fallback - scan the string */
    int byte_pos = 0;
    int grapheme_count = 0;
    UnicodeState state = {0};
    state.initialized = true;

    while (byte_pos < buffer->length && grapheme_count < grapheme_pos) {
      byte_pos = tl_next_grapheme_boundary(buffer->data, buffer->length,
                        byte_pos, &state);
      grapheme_count++;
    }

    return byte_pos;
  }

  /* Bounds check */
  if (grapheme_pos < 0) return 0;
  if (grapheme_pos >= buffer->grapheme_count) return buffer->length;

  /* Direct lookup */
  return buffer->grapheme_offsets[grapheme_pos];
}

/* tl_byte_to_grapheme_offset converts byte position to grapheme position. */
static inline int tl_byte_to_grapheme_offset(const TextBuffer *buffer, int byte_pos) {
  if (!buffer || !buffer->data) return 0;

  /* Handle case when grapheme boundaries aren't computed */
  if (!buffer->graphemes_valid || !buffer->grapheme_offsets) {
    /* Fallback - scan the string */
    int curr_pos = 0;
    int grapheme_count = 0;
    UnicodeState state = {0};
    state.initialized = true;

    while (curr_pos < byte_pos && curr_pos < buffer->length) {
      curr_pos = tl_next_grapheme_boundary(buffer->data, buffer->length,
                        curr_pos, &state);
      grapheme_count++;
    }

    return grapheme_count;
  }

  /* Bounds check */
  if (byte_pos <= 0) return 0;
  if (byte_pos >= buffer->length) return buffer->grapheme_count;

  /* Binary search to find the grapheme position */
  int low = 0;
  int high = buffer->grapheme_count - 1;

  while (low <= high) {
    int mid = low + (high - low) / 2;

    if (buffer->grapheme_offsets[mid] == byte_pos) {
      return mid;
    } else if (buffer->grapheme_offsets[mid] < byte_pos) {
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }

  /* Return the grapheme containing the byte position */
  return low > 0 ? low - 1 : 0;
}

/* tl_is_word_char determines if a codepoint is a word character. */
static inline bool tl_is_word_char(int codepoint) {
  if (codepoint < 0) return false;

  /* Use utf8proc to determine character category */
  const utf8proc_property_t *prop = utf8proc_get_property(codepoint);
  utf8proc_category_t category = (utf8proc_category_t)prop->category;

  /* Letters, numbers, and connector punctuation (including underscore) */
  return (category >= UTF8PROC_CATEGORY_LU && category <= UTF8PROC_CATEGORY_LO) ||
         (category >= UTF8PROC_CATEGORY_ND && category <= UTF8PROC_CATEGORY_NO) ||
         category == UTF8PROC_CATEGORY_PC;
}

/* tl_next_word_boundary finds the next word boundary position. */
static inline int tl_next_word_boundary(const char *str, int len, int pos) {
  if (!str || pos >= len) return len;

  /* Get current character type */
  int codepoint;
  pos = tl_next_codepoint(str, len, pos, &codepoint);
  if (pos >= len) return len;

  bool in_word = tl_is_word_char(codepoint);

  /* Skip all characters of the same type */
  while (pos < len) {
    int next_pos = tl_next_codepoint(str, len, pos, &codepoint);
    if (next_pos == pos) next_pos++; /* Prevent infinite loop */

    bool is_word = tl_is_word_char(codepoint);
    if (is_word != in_word) break;

    pos = next_pos;
  }

  /* If we were in non-word chars, skip following non-word chars */
  if (!in_word) {
    while (pos < len) {
      int next_pos = tl_next_codepoint(str, len, pos, &codepoint);
      if (next_pos == pos) next_pos++; /* Prevent infinite loop */

      if (tl_is_word_char(codepoint)) break;

      pos = next_pos;
    }
  }

  return pos;
}

/* tl_prev_word_boundary finds the previous word boundary position. */
static inline int tl_prev_word_boundary(const char *str, int pos) {
  if (!str || pos <= 0) return 0;

  /* Get previous character */
  int codepoint;
  int prev_pos = tl_prev_codepoint(str, pos, &codepoint);
  if (prev_pos <= 0) return 0;

  /* Check character type */
  bool in_word = tl_is_word_char(codepoint);

  /* Skip all characters of the same type */
  while (prev_pos > 0) {
    int start_pos = tl_prev_codepoint(str, prev_pos, &codepoint);
    if (start_pos == prev_pos) break; /* Prevent infinite loop */

    bool is_word = tl_is_word_char(codepoint);
    if (is_word != in_word) break;

    prev_pos = start_pos;
  }

  return prev_pos;
}

/* tl_calculate_width calculates the display width of a UTF-8 string. */
static inline int tl_calculate_width(const char *str, int len) {
  if (!str || len <= 0) return 0;

  int width = 0;
  int pos = 0;
  int in_ansi_escape = 0;

  while (pos < len) {
    /* Handle ANSI escape sequences */
    if (in_ansi_escape) {
      /* ANSI escape sequences end with a letter (m, H, J, etc.) */
      /* For color/formatting codes, typically it's 'm' */
      if ((str[pos] >= 'A' && str[pos] <= 'Z') ||
        (str[pos] >= 'a' && str[pos] <= 'z')) {
        in_ansi_escape = 0;
      }
      pos++;
      continue;
    }

    /* Check for start of ANSI escape sequence */
    if (pos + 1 < len && str[pos] == '\033' && str[pos + 1] == '[') {
      in_ansi_escape = 1;
      pos += 2;  /* Skip the "\033[" */
      continue;
    }

    /* Process normal character */
    int codepoint;
    int next_pos = tl_next_codepoint(str, len, pos, &codepoint);

    if (next_pos <= pos) {
      pos++;
      width++;
      continue;
    }

    /* Handle special cases */
    if (codepoint < 32) {
      if (codepoint == '\t') {
        width += 8 - (width % 8); /* Tab stop every 8 columns */
      }
      /* Other control chars don't advance width */
    } else {
        width += utf8proc_charwidth(codepoint);
    }

    pos = next_pos;
  }

  return width;
}

/* tl_update_grapheme_boundaries updates the grapheme boundary cache. */
static void tl_update_grapheme_boundaries(TextBuffer *buffer) {
  if (!buffer || !buffer->data) return;

  /* Initialize grapheme tracking if needed */
  if (buffer->grapheme_offsets) {
    buffer->grapheme_count = 0;
  } else {
    /* Initial allocation */
    int initial_capacity = buffer->length + 1;
    buffer->grapheme_offsets = (int *)malloc(initial_capacity * sizeof(int));
    if (!buffer->grapheme_offsets) {
      buffer->grapheme_capacity = 0;
      buffer->graphemes_valid = false;
      return;
    }
    buffer->grapheme_capacity = initial_capacity;
  }

  /* Process text to identify grapheme boundaries */
  int pos = 0;
  UnicodeState state = {0};
  state.initialized = true;

  /* First boundary is always position 0 */
  if (buffer->grapheme_count < buffer->grapheme_capacity) {
    buffer->grapheme_offsets[buffer->grapheme_count++] = 0;
  }

  while (pos < buffer->length) {
    int next_pos = tl_next_grapheme_boundary(buffer->data, buffer->length, pos, &state);
    if (next_pos <= pos) next_pos = pos + 1; /* Safety check */

    pos = next_pos;

    /* Add boundary if not at end */
    if (pos < buffer->length) {
      if (buffer->grapheme_count < buffer->grapheme_capacity) {
        buffer->grapheme_offsets[buffer->grapheme_count++] = pos;
      } else {
        /* Expand capacity */
        int new_capacity = buffer->grapheme_capacity * 2;
        int *new_offsets = (int *)realloc(buffer->grapheme_offsets,
                          new_capacity * sizeof(int));
        if (!new_offsets) {
          buffer->graphemes_valid = false;
          return;
        }

        buffer->grapheme_offsets = new_offsets;
        buffer->grapheme_capacity = new_capacity;
        buffer->grapheme_offsets[buffer->grapheme_count++] = pos;
      }
    }
  }

  buffer->graphemes_valid = true;
}

/*
 * Text Buffer Operations
 */

/* tl_buffer_init initializes a text buffer with the given capacity. */
static int tl_buffer_init(TextBuffer *buffer, int initial_size) {
  if (!buffer) return TERMLINE_ERROR_INVALID;
  if (initial_size < 16) initial_size = 16;

  /* Clear the struct first */
  memset(buffer, 0, sizeof(TextBuffer));

  /* Allocate text buffer */
  buffer->data = (char *)malloc((size_t)initial_size);
  if (!buffer->data) {
    return TERMLINE_ERROR_MEMORY;
  }

  buffer->capacity = initial_size;
  buffer->length = 0;
  buffer->data[0] = '\0';

  return TERMLINE_OK;
}

/* tl_buffer_free releases all resources owned by the buffer. */
static void tl_buffer_free(TextBuffer *buffer) {
  if (!buffer) return;

  if (buffer->data) {
    free(buffer->data);
    buffer->data = NULL;
    buffer->capacity = 0;
    buffer->length = 0;
  }

  if (buffer->grapheme_offsets) {
    free(buffer->grapheme_offsets);
    buffer->grapheme_offsets = NULL;
    buffer->grapheme_count = 0;
    buffer->grapheme_capacity = 0;
  }

  buffer->graphemes_valid = false;
}

/* tl_buffer_ensure_capacity ensures buffer can hold at least capacity bytes. */
static int tl_buffer_ensure_capacity(TextBuffer *buffer, int capacity) {
  if (!buffer || !buffer->data) return TERMLINE_ERROR_INVALID;
  if (capacity < 0) return TERMLINE_ERROR_INVALID;
  if (buffer->capacity >= capacity) {
    return TERMLINE_OK;
  }

  /* Calculate new size with overflow protection */
  int new_size = buffer->capacity;
  while (new_size < capacity) {
    if (new_size > INT_MAX / 2) {
      /* Avoid integer overflow */
      if (capacity > INT_MAX - 1) {
        return TERMLINE_ERROR_OVERFLOW;
      }
      new_size = capacity;
      break;
    }
    new_size *= 2;
  }

  /* Reallocate buffer */
  char *new_data = (char *)realloc(buffer->data, (size_t)new_size);
  if (!new_data) {
    return TERMLINE_ERROR_MEMORY;
  }

  buffer->data = new_data;
  buffer->capacity = new_size;

  return TERMLINE_OK;
}

/* tl_buffer_insert inserts text at the specified byte position. */
static int tl_buffer_insert(TextBuffer *buffer, int pos, const char *text, int len) {
  if (!buffer || !buffer->data) return TERMLINE_ERROR_INVALID;
  if (!text || len <= 0) {
    return TERMLINE_OK;
  }

  /* Validate position */
  if (pos < 0 || pos > buffer->length) {
    return TERMLINE_ERROR_INVALID;
  }

  /* Ensure buffer has enough capacity */
  int result = tl_buffer_ensure_capacity(buffer, buffer->length + len + 1);
  if (result != TERMLINE_OK) {
    return result;
  }

  /* Move existing text to make room */
  if (pos < buffer->length) {
    memmove(
      buffer->data + pos + len,
      buffer->data + pos,
      (size_t)(buffer->length - pos)
    );
  }

  /* Insert the new text */
  memcpy(buffer->data + pos, text, (size_t)len);
  buffer->length += len;
  buffer->data[buffer->length] = '\0';

  /* Invalidate grapheme boundaries */
  buffer->graphemes_valid = false;

  return TERMLINE_OK;
}

/* tl_buffer_delete removes text between start and end byte positions. */
static int tl_buffer_delete(TextBuffer *buffer, int start, int end) {
  if (!buffer || !buffer->data) return TERMLINE_ERROR_INVALID;
  if (start < 0 || end < 0 || start >= buffer->length || end <= start) {
    return TERMLINE_OK;
  }

  if (end > buffer->length) {
    end = buffer->length;
  }

  /* Move remaining text */
  if (end < buffer->length) {
    memmove(
      buffer->data + start,
      buffer->data + end,
      (size_t)(buffer->length - end)
    );
  }

  /* Update length */
  buffer->length -= (end - start);
  buffer->data[buffer->length] = '\0';

  /* Invalidate grapheme boundaries */
  buffer->graphemes_valid = false;

  return TERMLINE_OK;
}

/* tl_buffer_clear empties the buffer, preserving capacity. */
static int tl_buffer_clear(TextBuffer *buffer) {
  if (!buffer || !buffer->data) return TERMLINE_ERROR_INVALID;

  buffer->length = 0;
  buffer->data[0] = '\0';

  /* Reset grapheme tracking */
  buffer->grapheme_count = 0;
  buffer->graphemes_valid = false;

  return TERMLINE_OK;
}

/* tl_buffer_append adds text to the end of the buffer. */
static int tl_buffer_append(TextBuffer *buffer, const char *text, int len) {
  if (!buffer) return TERMLINE_ERROR_INVALID;
  return tl_buffer_insert(buffer, buffer->length, text, len);
}

/* tl_buffer_append_str adds a null-terminated string to the buffer. */
static int tl_buffer_append_str(TextBuffer *buffer, const char *text) {
  if (!buffer || !text) return TERMLINE_ERROR_INVALID;
  return tl_buffer_append(buffer, text, (int)strlen(text));
}

/* tl_buffer_to_string creates a new string from buffer contents. */
static char *tl_buffer_to_string(const TextBuffer *buffer) {
  if (!buffer || !buffer->data) return NULL;

  char *result = (char *)malloc((size_t)buffer->length + 1);
  if (!result) return NULL;

  memcpy(result, buffer->data, (size_t)buffer->length);
  result[buffer->length] = '\0';

  return result;
}

/*
 * Terminal I/O Functions
 */

/* tl_write writes data to a file descriptor with retry on EINTR. */
static int tl_write(int fd, const char *buf, size_t len) {
  size_t written = 0;
  ssize_t n;

  if (len == 0) return 0;
  if (fd < 0 || !buf) return TERMLINE_ERROR_INVALID;

  while (written < len) {
    n = write(fd, buf + written, len - written);
    if (n == -1) {
      if (errno == EINTR) {
        continue; /* Interrupted, retry */
      }
      return TERMLINE_ERROR_INPUT;
    }
    written += (size_t)n;
  }

  return (int)written;
}

/* tl_read_byte reads a single byte with EINTR handling. */
static int tl_read_byte(int fd) {
  unsigned char c;
  ssize_t n;

  if (fd < 0) return -1;

  do {
    n = read(fd, &c, 1);
  } while (n == -1 && errno == EINTR);

  if (n <= 0) return -1;
  return (int)c;
}

/* tl_read_byte_timeout reads a byte with timeout for escape sequences. */
static int tl_read_byte_timeout(int fd, int timeout_ms) {
  fd_set rfds;
  struct timeval tv;

  if (fd < 0 || timeout_ms < 0) return -1;

  /* Set up select parameters */
  FD_ZERO(&rfds);
  FD_SET(fd, &rfds);

  tv.tv_sec = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  /* Wait for data with EINTR handling */
  int retval;
  do {
    retval = select(fd + 1, &rfds, NULL, NULL, &tv);
  } while (retval == -1 && errno == EINTR);

  if (retval <= 0) {
    return -1; /* Timeout or error */
  }

  return tl_read_byte(fd);
}

/* tl_get_terminal_size retrieves terminal dimensions. */
static int tl_get_terminal_size(int fd, int *width, int *height) {
  if (!width || !height) return TERMLINE_ERROR_INVALID;

  /* Default values */
  *width = TL_DEFAULT_COLS;
  *height = TL_DEFAULT_ROWS;

#if defined(TIOCGWINSZ)
  /* Try ioctl first */
  struct winsize ws;
  if (ioctl(fd, TIOCGWINSZ, &ws) == 0) {
    if (ws.ws_col > 0) *width = ws.ws_col;
    if (ws.ws_row > 0) *height = ws.ws_row;
    return TERMLINE_OK;
  }
#endif

  /* Try environment variables as fallback */
  const char *cols_env = getenv("COLUMNS");
  const char *rows_env = getenv("LINES");

  if (cols_env) {
    int val = atoi(cols_env);
    if (val > 0) *width = val;
  }

  if (rows_env) {
    int val = atoi(rows_env);
    if (val > 0) *height = val;
  }

  return TERMLINE_OK;
}

/* Signal handler for window size changes */
static volatile sig_atomic_t tl_winch_received = 0;
static void tl_sigwinch_handler(int signum) {
  (void)signum;
  tl_winch_received = 1;
}

/* tl_setup_signal_handlers installs signal handlers for window resizing. */
static void tl_setup_signal_handlers(TermlineState *ts) {
  if (!ts) return;

  struct sigaction sa;

  sa.sa_handler = tl_sigwinch_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;

  sigaction(SIGWINCH, &sa, NULL);

  /* Reset the flag */
  tl_winch_received = 0;
  ts->terminal.winch_received = 0;
}

/* tl_reset_signal_handlers restores default signal handling. */
static void tl_reset_signal_handlers(void) {
  signal(SIGWINCH, SIG_DFL);
}

/* tl_handle_window_resize updates terminal size after resize. */
static void tl_handle_window_resize(TermlineState *ts) {
  if (!ts) return;

  if (tl_winch_received || ts->terminal.winch_received) {
    tl_get_terminal_size(ts->terminal.out_fd, &ts->display.width, &ts->display.height);

    /* Reset the flag */
    tl_winch_received = 0;
    ts->terminal.winch_received = 0;
  }
}

/* tl_set_terminal_mode puts terminal in raw mode for line editing. */
static int tl_set_terminal_mode(TermlineState *ts) {
  struct termios new_termios;

  if (!ts) return TERMLINE_ERROR_INVALID;
  if (ts->terminal.term_mode_set) {
    return TERMLINE_OK; /* Already in raw mode */
  }

  /* Save current terminal settings */
  if (tcgetattr(ts->terminal.in_fd, &ts->terminal.original) == -1) {
    return TERMLINE_ERROR_TERMINAL;
  }

  /* Create modified settings */
  new_termios = ts->terminal.original;

  /* Disable canonical mode, echo, and signals */
  new_termios.c_lflag &= ~(ICANON | ECHO | ISIG | IEXTEN);

  /* Disable flow control and CR to NL conversion */
  new_termios.c_iflag &= ~(IXON | ICRNL);

  /* Set character-by-character mode */
  new_termios.c_cc[VMIN] = 1;  /* Wait for at least one byte */
  new_termios.c_cc[VTIME] = 0; /* No timeout */

  /* Apply settings */
  if (tcsetattr(ts->terminal.in_fd, TCSAFLUSH, &new_termios) == -1) {
    return TERMLINE_ERROR_TERMINAL;
  }

  ts->terminal.term_mode_set = true;

  /* Set up signal handlers */
  tl_setup_signal_handlers(ts);

  return TERMLINE_OK;
}

/* tl_restore_terminal_mode restores original terminal settings. */
static void tl_restore_terminal_mode(TermlineState *ts) {
  if (!ts || !ts->terminal.term_mode_set) {
    return;
  }

  /* Restore original settings */
  tcsetattr(ts->terminal.in_fd, TCSAFLUSH, &ts->terminal.original);

  ts->terminal.term_mode_set = false;

  /* Reset signal handlers */
  tl_reset_signal_handlers();
}

/* tl_clear_screen clears the terminal display. */
static void tl_clear_screen(int fd) {
  if (fd < 0) return;
  tl_write(fd, "\033[2J\033[H", 7);
}

/*
 * Editor Operations
 */

/* tl_editor_insert_text inserts text at the cursor position. */
static int tl_editor_insert_text(TermlineState *ts, const char *text, int len) {
  if (!ts || !text || len <= 0) {
    return TERMLINE_OK;
  }

  /* Convert grapheme position to byte position */
  int byte_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);

  /* Insert text */
  int result = tl_buffer_insert(&ts->buffer, byte_pos, text, len);
  if (result != TERMLINE_OK) {
    return result;
  }

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Update cursor position */
  ts->editor.position = tl_byte_to_grapheme_offset(&ts->buffer, byte_pos + len);
  ts->editor.byte_position = byte_pos + len;

  return TERMLINE_OK;
}

/* tl_editor_delete_char deletes the character at the cursor position. */
static int tl_editor_delete_char(TermlineState *ts) {
  if (!ts || ts->editor.position >= ts->buffer.grapheme_count) {
    return TERMLINE_OK;
  }

  /* Get byte positions of the grapheme */
  int start_byte = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);
  int end_byte = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position + 1);

  /* Delete the grapheme */
  int result = tl_buffer_delete(&ts->buffer, start_byte, end_byte);
  if (result != TERMLINE_OK) {
    return result;
  }

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  return TERMLINE_OK;
}

/* tl_editor_backspace deletes the character before the cursor. */
static int tl_editor_backspace(TermlineState *ts) {
  if (!ts || ts->editor.position <= 0) {
    return TERMLINE_OK;
  }

  /* Get byte positions */
  int end_byte = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);
  int prev_grapheme = ts->editor.position - 1;
  int start_byte = tl_grapheme_to_byte_offset(&ts->buffer, prev_grapheme);

  /* Delete the grapheme */
  int result = tl_buffer_delete(&ts->buffer, start_byte, end_byte);
  if (result != TERMLINE_OK) {
    return result;
  }

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Update cursor position */
  ts->editor.position--;
  ts->editor.byte_position = start_byte;

  return TERMLINE_OK;
}

/* tl_editor_delete_word deletes from cursor to previous word boundary. */
static int tl_editor_delete_word(TermlineState *ts) {
  if (!ts || ts->editor.position <= 0) {
    return TERMLINE_OK;
  }

  /* Find word boundary */
  int curr_byte_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);
  int word_byte_pos = tl_prev_word_boundary(ts->buffer.data, curr_byte_pos);

  /* Convert to grapheme position */
  int word_pos = tl_byte_to_grapheme_offset(&ts->buffer, word_byte_pos);

  /* Delete the range */
  int result = tl_buffer_delete(&ts->buffer, word_byte_pos, curr_byte_pos);
  if (result != TERMLINE_OK) {
    return result;
  }

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Update cursor position */
  ts->editor.position = word_pos;
  ts->editor.byte_position = word_byte_pos;

  return TERMLINE_OK;
}

/* tl_editor_delete_to_end deletes from cursor to end of line. */
static int tl_editor_delete_to_end(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  /* Get cursor byte position */
  int curr_byte_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);

  /* Delete to end */
  int result = tl_buffer_delete(&ts->buffer, curr_byte_pos, ts->buffer.length);
  if (result != TERMLINE_OK) {
    return result;
  }

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  return TERMLINE_OK;
}

/* tl_editor_delete_line deletes the entire line and resets cursor. */
static int tl_editor_delete_line(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  /* Clear buffer */
  tl_buffer_clear(&ts->buffer);

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Reset cursor position */
  ts->editor.position = 0;
  ts->editor.byte_position = 0;

  return TERMLINE_OK;
}

/* tl_editor_move_left moves cursor left one grapheme. */
static int tl_editor_move_left(TermlineState *ts) {
  if (!ts || ts->editor.position <= 0) {
    return TERMLINE_OK;
  }

  /* Move cursor left by one grapheme */
  ts->editor.position--;

  /* Update byte position */
  ts->editor.byte_position = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);

  return TERMLINE_OK;
}

/* tl_editor_move_right moves cursor right one grapheme. */
static int tl_editor_move_right(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  /* Ensure grapheme boundaries are updated */
  if (!ts->buffer.graphemes_valid) {
    tl_update_grapheme_boundaries(&ts->buffer);
  }

  /* Check if at end */
  if (ts->editor.position >= ts->buffer.grapheme_count) {
    return TERMLINE_OK;
  }

  /* Move cursor right */
  ts->editor.position++;

  /* Update byte position */
  ts->editor.byte_position = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);

  return TERMLINE_OK;
}

/* tl_editor_move_to_start moves cursor to beginning of line. */
static int tl_editor_move_to_start(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  ts->editor.position = 0;
  ts->editor.byte_position = 0;

  return TERMLINE_OK;
}

/* tl_editor_move_to_end moves cursor to end of line. */
static int tl_editor_move_to_end(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  /* Ensure grapheme boundaries are updated */
  if (!ts->buffer.graphemes_valid) {
    tl_update_grapheme_boundaries(&ts->buffer);
  }

  ts->editor.position = ts->buffer.grapheme_count;
  ts->editor.byte_position = ts->buffer.length;

  return TERMLINE_OK;
}

/* tl_editor_move_prev_word moves cursor to previous word boundary. */
static int tl_editor_move_prev_word(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  /* Get current byte position */
  int curr_byte_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);

  /* Find previous word boundary */
  int word_pos = tl_prev_word_boundary(ts->buffer.data, curr_byte_pos);

  /* Update cursor position */
  ts->editor.position = tl_byte_to_grapheme_offset(&ts->buffer, word_pos);
  ts->editor.byte_position = word_pos;

  return TERMLINE_OK;
}

/* tl_editor_move_next_word moves cursor to next word boundary. */
static int tl_editor_move_next_word(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  /* Get current byte position */
  int curr_byte_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);

  /* Find next word boundary */
  int word_pos = tl_next_word_boundary(ts->buffer.data, ts->buffer.length, curr_byte_pos);

  /* Update cursor position */
  ts->editor.position = tl_byte_to_grapheme_offset(&ts->buffer, word_pos);
  ts->editor.byte_position = word_pos;

  return TERMLINE_OK;
}

/* tl_editor_transpose_chars swaps the characters around the cursor. */
static int tl_editor_transpose_chars(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  /* Need at least two graphemes and not at beginning */
  if (ts->buffer.grapheme_count < 2 || ts->editor.position < 1) {
    return TERMLINE_OK;
  }

  int curr_pos, prev_pos, next_pos;

  /* If at end, transpose the last two graphemes */
  if (ts->editor.position >= ts->buffer.grapheme_count) {
    prev_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position - 2);
    curr_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position - 1);
    next_pos = ts->buffer.length;
  } else {
    /* Otherwise, transpose current and previous */
    prev_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position - 1);
    curr_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);
    next_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position + 1);
  }

  /* Validate positions */
  if (prev_pos < 0 || curr_pos <= prev_pos || next_pos <= curr_pos) {
    return TERMLINE_OK;
  }

  /* Calculate lengths */
  int prev_len = curr_pos - prev_pos;
  int curr_len = next_pos - curr_pos;

  if (prev_len <= 0 || curr_len <= 0) {
    return TERMLINE_OK;
  }

  /* Perform the transpose */
  char *temp = (char *)malloc(curr_len);
  if (!temp) {
    return TERMLINE_ERROR_MEMORY;
  }

  /* Save current grapheme */
  memcpy(temp, ts->buffer.data + curr_pos, curr_len);

  /* Move previous grapheme forward */
  memmove(ts->buffer.data + prev_pos + curr_len, ts->buffer.data + prev_pos, prev_len);

  /* Put current grapheme at the beginning */
  memcpy(ts->buffer.data + prev_pos, temp, curr_len);

  free(temp);

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Move cursor after the transposed characters */
  ts->editor.position = tl_byte_to_grapheme_offset(&ts->buffer, prev_pos + curr_len + prev_len);
  ts->editor.byte_position = prev_pos + curr_len + prev_len;

  return TERMLINE_OK;
}

/*
 * History Operations
 */

/* tl_history_prev navigates to the previous history entry. */
static int tl_history_prev(TermlineState *ts) {
  if (!ts || !ts->history.history || ts->history.index <= 0) {
    return TERMLINE_OK;
  }

  /* Save current line if first time navigating to history */
  if (ts->history.index == ts->history.history->length && !ts->history.saved_line) {
    ts->history.saved_line = strdup(ts->buffer.data);
    if (!ts->history.saved_line && ts->buffer.length > 0) {
      return TERMLINE_ERROR_MEMORY;
    }
  }

  ts->history.index--;

  /* Load history entry */
  const char *line = ts->history.history->lines[ts->history.index];
  if (!line) {
    /* Invalid entry, restore index */
    ts->history.index++;
    return TERMLINE_OK;
  }

  /* Replace current buffer */
  tl_buffer_clear(&ts->buffer);
  tl_buffer_append_str(&ts->buffer, line);

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Move cursor to end */
  ts->editor.position = ts->buffer.grapheme_count;
  ts->editor.byte_position = ts->buffer.length;

  return TERMLINE_OK;
}

/* tl_history_next navigates to the next history entry. */
static int tl_history_next(TermlineState *ts) {
  if (!ts || !ts->history.history || ts->history.index >= ts->history.history->length) {
    return TERMLINE_OK;
  }

  ts->history.index++;

  if (ts->history.index == ts->history.history->length) {
    /* Reached end of history, restore saved line */
    tl_buffer_clear(&ts->buffer);

    if (ts->history.saved_line) {
      tl_buffer_append_str(&ts->buffer, ts->history.saved_line);
      free(ts->history.saved_line);
      ts->history.saved_line = NULL;
    }
  } else {
    /* Load history entry */
    const char *line = ts->history.history->lines[ts->history.index];
    if (!line) {
      /* Invalid entry, restore index */
      ts->history.index--;
      return TERMLINE_OK;
    }

    tl_buffer_clear(&ts->buffer);
    tl_buffer_append_str(&ts->buffer, line);
  }

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Move cursor to end */
  ts->editor.position = ts->buffer.grapheme_count;
  ts->editor.byte_position = ts->buffer.length;

  return TERMLINE_OK;
}

/* tl_history_add_line adds the current line to history. */
static int tl_history_add_line(TermlineState *ts) {
  if (!ts || !ts->history.history || ts->buffer.length == 0) {
    return TERMLINE_OK;
  }

  return termline_history_add(ts->history.history, ts->buffer.data);
}

/*
 * Display Functions
 */

/* tl_refresh_line updates the terminal display for the current line. */
static void tl_refresh_line(TermlineState *ts) {
  if (!ts) return;

  /* Clear current line */
  tl_write(ts->terminal.out_fd, "\r\033[K", 4);

  /* Write prompt */
  tl_write(ts->terminal.out_fd, ts->prompt, (size_t)ts->prompt_len);

  /* Write buffer content */
  if (ts->buffer.length > 0) {
      tl_write(ts->terminal.out_fd, ts->buffer.data, (size_t)ts->buffer.length);
  }

  /* Calculate prompt width if needed */
  ts->display.prompt_width = tl_calculate_width(ts->prompt, ts->prompt_len);

  /* Ensure grapheme boundaries are valid */
  if (!ts->buffer.graphemes_valid) {
      tl_update_grapheme_boundaries(&ts->buffer);
  }

  /* Calculate cursor position */
  int cursor_byte_pos = tl_grapheme_to_byte_offset(&ts->buffer, ts->editor.position);
  int cursor_col = ts->display.prompt_width + tl_calculate_width(ts->buffer.data, cursor_byte_pos);

  /* Position cursor */
  char seq[32];
  snprintf(seq, sizeof(seq), "\r\033[%dC", cursor_col);
  tl_write(ts->terminal.out_fd, seq, strlen(seq));
}

/*
 * Key Handling Function
 */

/* tl_handle_key processes a key press and performs the appropriate action. */
static int tl_handle_key(TermlineState *ts, int key) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  switch (key) {
    /* Line completion */
    case TL_KEY_ENTER:
    case TL_KEY_CTRL_J:
      if (ts->buffer.length > 0) {
        tl_history_add_line(ts);
      }
      return TERMLINE_KEY_COMPLETE;

    case TL_KEY_CTRL_C:
      tl_write(ts->terminal.out_fd, "^C", 2);
      return TERMLINE_KEY_CANCEL;

    /* Delete operations */
    case TL_KEY_BACKSPACE:
    case TL_KEY_CTRL_H:
      tl_editor_backspace(ts);
      break;

    case TL_KEY_CTRL_D:
      if (ts->buffer.length > 0) {
        tl_editor_delete_char(ts);
      } else {
        return TERMLINE_KEY_EOF;
      }
      break;

    /* Cursor movement */
    case TL_KEY_CTRL_B:
      tl_editor_move_left(ts);
      break;

    case TL_KEY_CTRL_F:
      tl_editor_move_right(ts);
      break;

    case TL_KEY_CTRL_A:
      tl_editor_move_to_start(ts);
      break;

    case TL_KEY_CTRL_E:
      tl_editor_move_to_end(ts);
      break;

    case TL_KEY_CTRL_P:
      tl_history_prev(ts);
      break;

    case TL_KEY_CTRL_N:
      tl_history_next(ts);
      break;

    /* Edit operations */
    case TL_KEY_CTRL_T:
      tl_editor_transpose_chars(ts);
      break;

    case TL_KEY_CTRL_U:
      tl_editor_delete_line(ts);
      break;

    case TL_KEY_CTRL_K:
      tl_editor_delete_to_end(ts);
      break;

    case TL_KEY_CTRL_W:
      tl_editor_delete_word(ts);
      break;

    /* Screen operations */
    case TL_KEY_CTRL_L:
      tl_clear_screen(ts->terminal.out_fd);
      break;

    case TL_KEY_TAB:
      /* Tab completion */
      if (ts->completion.completion_func) {
        tl_update_completions(ts);
        tl_complete_next(ts);
      } else {
        /* Insert a tab if no completion function */
        char tab = '\t';
        tl_editor_insert_text(ts, &tab, 1);
      }
      break;

    case TL_KEY_ESC:
      /* Process escape sequences for special keys */
      key = tl_read_byte_timeout(ts->terminal.in_fd, TL_KEY_TIMEOUT_MS);
      if (key < 0) {
        break; /* Standalone ESC or timeout */
      }

      if (key == '[') {
        /* CSI sequence */
        unsigned char seq[TL_KEY_SEQUENCE_MAX];
        int seq_len = 0;

        /* Read until final byte */
        while (seq_len < TL_KEY_SEQUENCE_MAX - 1) {
          key = tl_read_byte_timeout(ts->terminal.in_fd, TL_KEY_TIMEOUT_MS);
          if (key < 0) break;

          seq[seq_len++] = (unsigned char)key;

          if (key >= 0x40 && key <= 0x7E) {
            break;
          }
        }

        /* Process based on final byte */
        if (seq_len > 0) {
          switch (seq[seq_len - 1]) {
            case 'A': /* Up arrow */
              tl_history_prev(ts);
              break;

            case 'B': /* Down arrow */
              tl_history_next(ts);
              break;

            case 'C': /* Right arrow */
              tl_editor_move_right(ts);
              break;

            case 'D': /* Left arrow */
              tl_editor_move_left(ts);
              break;

            case 'H': /* Home */
              tl_editor_move_to_start(ts);
              break;

            case 'F': /* End */
              tl_editor_move_to_end(ts);
              break;

            case '~':
              /* Extended keys */
              if (seq_len >= 2) {
                if (seq[0] == '1' || seq[0] == '7') {
                  tl_editor_move_to_start(ts);
                } else if (seq[0] == '3') {
                  tl_editor_delete_char(ts);
                } else if (seq[0] == '4' || seq[0] == '8') {
                  tl_editor_move_to_end(ts);
                }
              }
              break;
          }
        }
      } else if (key == 'O') {
        /* SS3 sequence */
        key = tl_read_byte_timeout(ts->terminal.in_fd, TL_KEY_TIMEOUT_MS);
        if (key >= 0) {
          switch (key) {
            case 'A': /* Up arrow */
              tl_history_prev(ts);
              break;

            case 'B': /* Down arrow */
              tl_history_next(ts);
              break;

            case 'C': /* Right arrow */
              tl_editor_move_right(ts);
              break;

            case 'D': /* Left arrow */
              tl_editor_move_left(ts);
              break;

            case 'H': /* Home */
              tl_editor_move_to_start(ts);
              break;

            case 'F': /* End */
              tl_editor_move_to_end(ts);
              break;
          }
        }
      } else {
        /* Alt/Meta key combinations */
        switch (key) {
          case 'b': /* Alt-b: backward word */
            tl_editor_move_prev_word(ts);
            break;

          case 'f': /* Alt-f: forward word */
            tl_editor_move_next_word(ts);
            break;
        }
      }
      break;

    /* Regular character */
    default:
      if (key >= 32 || key == TL_KEY_TAB) {
        char ch[1] = { (char)key };
        tl_editor_insert_text(ts, ch, 1);
      }
      break;
  }

  return TERMLINE_KEY_HANDLED;
}

/*
 * Completion Functions
 */

/* tl_update_completions calls the completion callback and updates state. */
static int tl_update_completions(TermlineState *ts) {
  if (!ts || !ts->completion.completion_func) {
    return TERMLINE_ERROR_INVALID;
  }

  /* Free existing completions */
  tl_free_completions(ts);

  /* Get new completions */
  ts->completion.completions = ts->completion.completion_func(
    ts->buffer.data,
    0,
    ts->buffer.length,
    ts->completion.completion_data
  );

  /* Count completions */
  if (ts->completion.completions) {
    int count = 0;
    while (ts->completion.completions[count] != NULL) {
      count++;
    }
    ts->completion.completion_count = count;
    ts->completion.completion_index = -1;
  }

  return ts->completion.completion_count > 0 ? TERMLINE_OK : TERMLINE_ERROR_INVALID;
}

/* tl_free_completions releases memory used by completions. */
static void tl_free_completions(TermlineState *ts) {
  if (!ts || !ts->completion.completions) {
    return;
  }

  for (int i = 0; i < ts->completion.completion_count; i++) {
    if (ts->completion.completions[i]) {
      free(ts->completion.completions[i]);
    }
  }

  free(ts->completion.completions);
  ts->completion.completions = NULL;
  ts->completion.completion_count = 0;
  ts->completion.completion_index = -1;
}

/* tl_complete_next selects the next completion from available options. */
static int tl_complete_next(TermlineState *ts) {
  if (!ts || !ts->completion.completions || ts->completion.completion_count <= 0) {
    return TERMLINE_ERROR_INVALID;
  }

  /* Save original text on first completion */
  if (ts->completion.completion_index == -1) {
    if (ts->history.saved_line) {
      free(ts->history.saved_line);
      ts->history.saved_line = NULL;
    }
    ts->history.saved_line = strdup(ts->buffer.data);
    if (!ts->history.saved_line && ts->buffer.length > 0) {
      return TERMLINE_ERROR_MEMORY;
    }
  }

  /* Select next completion */
  ts->completion.completion_index = (ts->completion.completion_index + 1) %
                    ts->completion.completion_count;

  /* Apply completion */
  tl_buffer_clear(&ts->buffer);
  tl_buffer_append_str(&ts->buffer, ts->completion.completions[ts->completion.completion_index]);

  /* Update grapheme boundaries */
  tl_update_grapheme_boundaries(&ts->buffer);

  /* Move cursor to end */
  ts->editor.position = ts->buffer.grapheme_count;
  ts->editor.byte_position = ts->buffer.length;

  return TERMLINE_OK;
}

/*
 * State Initialization/Cleanup
 */

/* tl_create_state initializes a line editing session. */
static TermlineState *tl_create_state(TermlineContext *ctx, const char *prompt, int in_fd, int out_fd) {
  if (in_fd < 0 || out_fd < 0) return NULL;

  TermlineState *ts = (TermlineState *)calloc(1, sizeof(TermlineState));
  if (!ts) return NULL;

  /* Initialize buffer */
  if (tl_buffer_init(&ts->buffer, TL_INITIAL_BUFFER_SIZE) != TERMLINE_OK) {
    free(ts);
    return NULL;
  }

  /* Set file descriptors */
  ts->terminal.in_fd = in_fd;
  ts->terminal.out_fd = out_fd;

  /* Set prompt */
  ts->prompt = prompt ? prompt : "";
  ts->prompt_len = (int)strlen(ts->prompt);

  /* Set context */
  ts->ctx = ctx;

  /* Initialize history from context */
  if (ctx) {
    ts->history.history = ctx->history;
    if (ts->history.history) {
      ts->history.index = ts->history.history->length;
    }

    /* Set completion callback from context */
    ts->completion.completion_func = ctx->completion_func;
    ts->completion.completion_data = ctx->completion_data;
  }

  /* Initialize editor state */
  ts->editor.position = 0;
  ts->editor.byte_position = 0;

  /* Initialize Unicode state */
  ts->unicode.grapheme_state = 0;
  ts->unicode.initialized = true;

  /* Get terminal size */
  tl_get_terminal_size(out_fd, &ts->display.width, &ts->display.height);

  /* Calculate prompt width */
  ts->display.prompt_width = tl_calculate_width(ts->prompt, ts->prompt_len);

  return ts;
}

/* tl_free_state releases all resources owned by the session. */
static void tl_free_state(TermlineState *ts) {
  if (!ts) return;

  /* Ensure terminal is restored */
  if (ts->terminal.term_mode_set) {
    tl_restore_terminal_mode(ts);
  }

  /* Free buffer */
  tl_buffer_free(&ts->buffer);

  /* Free saved history line */
  if (ts->history.saved_line) {
    free(ts->history.saved_line);
  }

  /* Free completions */
  tl_free_completions(ts);

  /* Clear ctx reference if we're the current state */
  if (ts->ctx && ts->ctx->state == ts) {
    ts->ctx->state = NULL;
  }

  /* Free the state structure */
  free(ts);
}

/* tl_process_input handles the main line editing loop. */
static int tl_process_input(TermlineState *ts) {
  if (!ts) return TERMLINE_ERROR_INVALID;

  int key, result;

  /* Main editing loop */
  while (1) {
    /* Check for window resize */
    tl_handle_window_resize(ts);

    /* Refresh the display */
    tl_refresh_line(ts);

    /* Read next key */
    key = tl_read_byte(ts->terminal.in_fd);
    if (key < 0) {
      return TERMLINE_ERROR_INPUT;
    }

    /* Process key */
    result = tl_handle_key(ts, key);

    if (result != TERMLINE_KEY_HANDLED) {
      return result;
    }
  }
}

/*
 * Public API Implementation
 */

/* termline_context_create creates a new context for thread-safe operations. */
TermlineContext *termline_context_create(void) {
  TermlineContext *ctx = (TermlineContext *)calloc(1, sizeof(TermlineContext));
  return ctx;
}

/* termline_context_destroy frees all resources associated with a context. */
void termline_context_destroy(TermlineContext *ctx) {
  if (!ctx) return;

  /* Make local copies to prevent recursive access issues */
  TermlineHistory *history = ctx->history;
  TermlineState *state = ctx->state;

  /* Clear pointers first */
  ctx->history = NULL;
  ctx->state = NULL;

  /* Free state if owned */
  if (state) {
    state->ctx = NULL;
    tl_free_state(state);
  }

  /* Free history if owned */
  if (history) {
    termline_history_destroy(history);
  }

  /* Free the context itself */
  free(ctx);
}

/* termline_readline_internal provides internal implementation shared by all readline variants. */
static char *termline_readline_internal(TermlineContext *ctx, const char *prompt, int in_fd, int out_fd) {
  TermlineState *ts;
  char *line = NULL;

  /* Create session state */
  ts = tl_create_state(ctx, prompt, in_fd, out_fd);
  if (!ts) {
    return NULL;
  }

  /* Configure terminal */
  if (tl_set_terminal_mode(ts) != TERMLINE_OK) {
    tl_free_state(ts);
    return NULL;
  }

  /* Process input until complete */
  int result = tl_process_input(ts);

  /* Restore terminal */
  tl_restore_terminal_mode(ts);

  /* Output newline */
  tl_write(ts->terminal.out_fd, "\n", 1);

  /* Handle result */
  if (result == TERMLINE_KEY_COMPLETE) {
    line = tl_buffer_to_string(&ts->buffer);

    /* Add to history if non-empty */
    if (ctx && ctx->history && line && *line) {
      termline_history_add(ctx->history, line);
    }
  } else if (result == TERMLINE_KEY_CANCEL) {
    line = strdup("");
  } else {
    line = NULL;
  }

  /* Clean up */
  tl_free_state(ts);

  return line;
}

/* termline_readline reads a line from stdin with the given prompt. */
char *termline_readline(const char *prompt) {
  return termline_readline_internal(NULL, prompt, STDIN_FILENO, STDOUT_FILENO);
}

/* termline_readline_ctx reads a line using the specified context. */
char *termline_readline_ctx(TermlineContext *ctx, const char *prompt) {
  return termline_readline_internal(ctx, prompt, STDIN_FILENO, STDOUT_FILENO);
}

/* termline_readline_fd reads a line from custom file descriptors. */
char *termline_readline_fd(const char *prompt, int in_fd, int out_fd) {
  return termline_readline_internal(NULL, prompt, in_fd, out_fd);
}

/* termline_readline_fd_ctx reads a line with custom fd and context. */
char *termline_readline_fd_ctx(TermlineContext *ctx, const char *prompt, int in_fd, int out_fd) {
  return termline_readline_internal(ctx, prompt, in_fd, out_fd);
}

/* termline_free safely frees memory allocated by any termline function. */
void termline_free(void *ptr) {
  if (ptr) {
    free(ptr);
  }
}

/* termline_history_create creates a new history with specified capacity. */
TermlineHistory *termline_history_create(int max_capacity) {
  if (max_capacity <= 0) {
    return NULL;
  }

  TermlineHistory *history = (TermlineHistory *)calloc(1, sizeof(TermlineHistory));
  if (!history) {
    return NULL;
  }

  history->lines = (char **)calloc((size_t)max_capacity, sizeof(char *));
  if (!history->lines) {
    free(history);
    return NULL;
  }

  history->length = 0;
  history->capacity = max_capacity;
  history->allow_dups = false;

  return history;
}

/* termline_history_destroy frees all resources associated with history. */
void termline_history_destroy(TermlineHistory *history) {
  if (!history) {
    return;
  }

  if (history->lines) {
    for (int i = 0; i < history->length; i++) {
      if (history->lines[i]) {
        free(history->lines[i]);
      }
    }
    free(history->lines);
  }

  free(history);
}

/* termline_history_set_ctx attaches history to the specified context. */
void termline_history_set_ctx(TermlineContext *ctx, TermlineHistory *history) {
  if (ctx) {
    ctx->history = history;
  }
}

/* termline_history_add adds a line to history, returns 1 if added, 0 if duplicate. */
int termline_history_add(TermlineHistory *history, const char *line) {
  if (!history || !line || *line == '\0') {
    return 0;
  }

  /* Check for duplicate if not allowed */
  if (!history->allow_dups) {
    for (int i = 0; i < history->length; i++) {
      if (history->lines[i] && strcmp(history->lines[i], line) == 0) {
        /* Move to most recent position */
        if (i < history->length - 1) {
          char *temp = history->lines[i];
          memmove(&history->lines[i], &history->lines[i+1],
                  sizeof(char *) * (size_t)(history->length - i - 1));
          history->lines[history->length - 1] = temp;
        }
        return 0;
      }
    }
  }

  /* Create a copy of the line */
  char *copy = strdup(line);
  if (!copy) {
    return -1;
  }

  /* If history is full, remove oldest entry */
  if (history->length == history->capacity) {
    free(history->lines[0]);
    memmove(&history->lines[0], &history->lines[1],
            sizeof(char *) * (size_t)(history->length - 1));
    history->length--;
  }

  /* Add new entry */
  history->lines[history->length] = copy;
  history->length++;

  return 1;
}

/* termline_history_save writes history to a file, returns 0 on success. */
int termline_history_save(TermlineHistory *history, const char *filename) {
  FILE *fp;

  if (!history || !filename) {
    return -1;
  }

  fp = fopen(filename, "w");
  if (!fp) {
    return -1;
  }

  for (int i = 0; i < history->length; i++) {
    if (history->lines[i]) {
      fprintf(fp, "%s\n", history->lines[i]);
    }
  }

  fclose(fp);
  return 0;
}

/* termline_history_load reads history from a file, returns 0 on success. */
int termline_history_load(TermlineHistory *history, const char *filename) {
  FILE *fp;
  char buf[4096];

  if (!history || !filename) {
    return -1;
  }

  fp = fopen(filename, "r");
  if (!fp) {
    return -1;
  }

  while (fgets(buf, sizeof(buf), fp)) {
    size_t len = strlen(buf);

    /* Remove trailing newline */
    if (len > 0 && buf[len-1] == '\n') {
      buf[len-1] = '\0';
    }

    termline_history_add(history, buf);
  }

  fclose(fp);
  return 0;
}

/* termline_history_allow_duplicates configures whether duplicates are allowed. */
void termline_history_allow_duplicates(TermlineHistory *history, bool allow) {
  if (history) {
    history->allow_dups = allow;
  }
}

/* termline_set_completion_callback sets the tab completion handler. */
void termline_set_completion_callback(TermlineContext *ctx,
                                      TermlineCompletionCallback callback,
                                      void *userdata) {
  if (ctx) {
    ctx->completion_func = callback;
    ctx->completion_data = userdata;
  }
}

#endif /* TERMLINE_IMPLEMENTATION */
