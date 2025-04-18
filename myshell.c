/*
 * myshell.c provides a simple, embeddable POSIX shell.
 *
 * Copyright 2025 Dair Aidarkhanov
 * SPDX-License-Identifier: 0BSD
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <pthread.h>
#include <termios.h>

#define TERMLINE_IMPLEMENTATION
#include "termline.h"

#define MAX_INPUT_LENGTH 8192
#define MAX_TOKEN_LENGTH 1024
#define MAX_LINE_LENGTH 4096
#define MAX_PATH_LENGTH 1024
#define MAX_ARGS 256
#define MAX_ENV_VARS 1024
#define MAX_FUNCTIONS 256
#define MAX_ALIASES 256
#define MAX_HISTORY 1000
#define MAX_JOBS 128

typedef enum {
  MYSH_OK = 0,
  MYSH_ERROR_SYNTAX,
  MYSH_ERROR_COMMAND_NOT_FOUND,
  MYSH_ERROR_INVALID_ARGUMENT,
  MYSH_ERROR_MEMORY,
  MYSH_ERROR_IO,
  MYSH_ERROR_INTERRUPTED,
  MYSH_ERROR_UNKNOWN
} MyshErrorCode;

typedef enum {
  TOKEN_WORD,
  TOKEN_OPERATOR,
  TOKEN_REDIRECT,
  TOKEN_VARIABLE,
  TOKEN_CMDSUBST,
  TOKEN_COMMENT,
  TOKEN_NEWLINE,
  TOKEN_EOF,
  TOKEN_ERROR
} TokenType;

typedef enum {
  OP_NONE,
  OP_PIPE,       /* | */
  OP_BACKGROUND, /* & */
  OP_SEMICOLON,  /* ; */
  OP_AND,        /* && */
  OP_OR,         /* || */
  OP_LPAREN,     /* ( */
  OP_RPAREN,     /* ) */
  OP_LBRACE,     /* { */
  OP_RBRACE      /* } */
} OperatorType;

typedef enum {
  REDIR_NONE,
  REDIR_IN,      /* < */
  REDIR_OUT,     /* > */
  REDIR_APPEND,  /* >> */
  REDIR_HEREDOC, /* << */
  REDIR_DUPFD    /* >& */
} RedirectionType;

typedef enum {
  NODE_COMMAND,
  NODE_PIPELINE,
  NODE_LIST,
  NODE_REDIRECTION,
  NODE_ASSIGNMENT,
  NODE_IF,
  NODE_WHILE,
  NODE_FOR,
  NODE_FUNCTION,
  NODE_SUBSHELL,
  NODE_CMDSUBST
} NodeType;

typedef enum { JOB_RUNNING, JOB_STOPPED, JOB_DONE } JobStatus;

typedef struct {
  TokenType type;
  char *value;
  size_t length;
  size_t line;
  size_t column;
  union {
    OperatorType op;
    RedirectionType redir;
  };
} Token;

typedef struct {
  RedirectionType type;
  int fd;           /* File descriptor to redirect */
  char *target;     /* Target file or fd */
  bool close_after; /* Whether to close after command */
} Redirection;

typedef struct {
  pid_t pid;             /* Process ID of the job */
  char *command;         /* Command string */
  JobStatus status;      /* Current status */
  atomic_bool in_use;    /* Whether this job slot is used */
  struct termios tmodes; /* Terminal modes */
} Job;

struct Node;
struct CommandNode;
struct PipelineNode;
struct ListNode;
struct RedirectionNode;
struct AssignmentNode;
struct IfNode;
struct WhileNode;
struct ForNode;
struct FunctionNode;
struct SubshellNode;
struct CmdSubstNode;

typedef struct Node {
  NodeType type;
  struct Node *next;

  union {
    struct CommandNode *command;
    struct PipelineNode *pipeline;
    struct ListNode *list;
    struct RedirectionNode *redirection;
    struct AssignmentNode *assignment;
    struct IfNode *if_node;
    struct WhileNode *while_node;
    struct ForNode *for_node;
    struct FunctionNode *function;
    struct SubshellNode *subshell;
    struct CmdSubstNode *cmdsubst;
  };
} Node;

typedef struct CommandNode {
  char *name;
  char **args;
  size_t arg_count;
  Redirection *redirections;
  size_t redir_count;
  bool background;
} CommandNode;

typedef struct PipelineNode {
  Node **commands;
  size_t command_count;
  bool background;
} PipelineNode;

typedef struct ListNode {
  Node **commands;
  size_t command_count;
  OperatorType *operators;
} ListNode;

typedef struct RedirectionNode {
  Node *command;
  Redirection *redirections;
  size_t redir_count;
} RedirectionNode;

typedef struct AssignmentNode {
  char *name;
  char *value;
  bool export;
} AssignmentNode;

typedef struct IfNode {
  Node *condition;
  Node *then_part;
  Node *else_part;
} IfNode;

typedef struct WhileNode {
  Node *condition;
  Node *body;
  bool until; /* True if this is an until loop */
} WhileNode;

typedef struct ForNode {
  char *var_name;
  char **words;
  size_t word_count;
  Node *body;
} ForNode;

typedef struct FunctionNode {
  char *name;
  Node *body;
} FunctionNode;

typedef struct SubshellNode {
  Node *command;
} SubshellNode;

typedef struct CmdSubstNode {
  Node *command;
} CmdSubstNode;

typedef struct {
  char *name;
  char *value;
  bool readonly;
  bool exported;
  atomic_bool in_use; /* For thread safety */
} Variable;

typedef struct {
  char *name;
  Node *body;
  atomic_bool in_use; /* For thread safety */
} Function;

typedef struct {
  char *name;
  char *value;
  atomic_bool in_use; /* For thread safety */
} Alias;

typedef struct EnvScope {
  Variable **variables;
  size_t var_count;
  size_t var_capacity;
  struct EnvScope *parent;
  pthread_mutex_t mutex;
} EnvScope;

typedef struct {
  /* Input state */
  char *input;
  size_t input_length;
  size_t input_pos;
  size_t input_line;
  size_t input_column;

  /* Lexer state */
  Token current_token;

  /* Parser state */
  Node *ast_root;

  /* Environment state */
  EnvScope *global_scope;
  EnvScope *current_scope;
  Function *functions[MAX_FUNCTIONS];
  size_t function_count;
  Alias *aliases[MAX_ALIASES];
  size_t alias_count;

  /* Execution state */
  int last_exit_code;
  bool interactive;
  char cwd[MAX_PATH_LENGTH];

  /* Job control state */
  Job jobs[MAX_JOBS];
  size_t job_count;
  pid_t shell_pgid;
  int terminal_fd;
  struct termios original_termios;
  bool job_control_active;

  /* Embedding info */
  void (*error_callback)(const char *, size_t, size_t, const char *);

  /* Thread safety */
  pthread_mutex_t mutex;
  atomic_bool is_running;

  /* Readline state */
  TermlineContext *termline_ctx;
  TermlineHistory *history;
} ShellContext;

/* Memory management */
static void *mysh_malloc(size_t size);
static void *mysh_realloc(void *ptr, size_t size);
static char *mysh_strdup(const char *str);
static void mysh_free(void *ptr);

/* Context management */
static ShellContext *mysh_create_context(void);
static void mysh_destroy_context(ShellContext *ctx);
static void mysh_reset_context(ShellContext *ctx);

/* Environment functions */
static EnvScope *mysh_create_scope(EnvScope *parent);
static void mysh_destroy_scope(EnvScope *scope);
static Variable *mysh_get_variable(ShellContext *ctx, const char *name);
static Variable *mysh_set_variable(ShellContext *ctx, const char *name,
                                   const char *value);
static void mysh_export_variable(ShellContext *ctx, const char *name);
static char *mysh_expand_variable(ShellContext *ctx, const char *name);
static Function *mysh_get_function(ShellContext *ctx, const char *name);
static Function *mysh_set_function(ShellContext *ctx, const char *name,
                                   Node *body);
static Alias *mysh_get_alias(ShellContext *ctx, const char *name);
static Alias *mysh_set_alias(ShellContext *ctx, const char *name,
                             const char *value);
static void mysh_push_scope(ShellContext *ctx);
static void mysh_pop_scope(ShellContext *ctx);

/* Lexer functions */
static Token mysh_scan_token(ShellContext *ctx);
static void mysh_init_lexer(ShellContext *ctx, const char *input);
static char mysh_peek_char(ShellContext *ctx);
static char mysh_advance_char(ShellContext *ctx);
static bool mysh_is_at_end(ShellContext *ctx);
static void mysh_skip_whitespace(ShellContext *ctx);
static Token mysh_scan_word(ShellContext *ctx);
static Token mysh_scan_operator(ShellContext *ctx);
static Token mysh_scan_redirect(ShellContext *ctx);
static Token mysh_scan_variable(ShellContext *ctx);
static Token mysh_scan_cmdsubst(ShellContext *ctx);
static Token mysh_scan_comment(ShellContext *ctx);
static void mysh_free_token(Token *token);

/* Parser functions */
static void mysh_init_parser(ShellContext *ctx);
static Token mysh_current_token(ShellContext *ctx);
static Token mysh_advance_token(ShellContext *ctx);
static bool mysh_check_token(ShellContext *ctx, TokenType type);
static bool mysh_match_token(ShellContext *ctx, TokenType type);
static Node *mysh_parse(ShellContext *ctx);
static Node *mysh_parse_list(ShellContext *ctx);
static Node *mysh_parse_pipeline(ShellContext *ctx);
static Node *mysh_parse_command(ShellContext *ctx);
static Node *mysh_parse_assignment(ShellContext *ctx);
static Node *mysh_parse_if(ShellContext *ctx);
static Node *mysh_parse_while(ShellContext *ctx);
static Node *mysh_parse_for(ShellContext *ctx);
static Node *mysh_parse_function(ShellContext *ctx);
static Node *mysh_parse_subshell(ShellContext *ctx);
static Node *mysh_parse_cmdsubst(ShellContext *ctx);
static void mysh_free_node(Node *node);

/* Execution functions */
static int mysh_execute(ShellContext *ctx, Node *node);
static int mysh_execute_command(ShellContext *ctx, CommandNode *command);
static int mysh_execute_pipeline(ShellContext *ctx, PipelineNode *pipeline);
static int mysh_execute_list(ShellContext *ctx, ListNode *list);
static int mysh_execute_redirection(ShellContext *ctx,
                                    RedirectionNode *redirection);
static int mysh_execute_assignment(ShellContext *ctx,
                                   AssignmentNode *assignment);
static int mysh_execute_if(ShellContext *ctx, IfNode *if_node);
static int mysh_execute_while(ShellContext *ctx, WhileNode *while_node);
static int mysh_execute_for(ShellContext *ctx, ForNode *for_node);
static int mysh_execute_function(ShellContext *ctx, FunctionNode *function);
static int mysh_execute_subshell(ShellContext *ctx, SubshellNode *subshell);
static int mysh_execute_cmdsubst(ShellContext *ctx, CmdSubstNode *cmdsubst,
                                 char **output);
static int mysh_execute_builtin(ShellContext *ctx, CommandNode *command);
static int mysh_execute_external(ShellContext *ctx, CommandNode *command);
static char *mysh_expand_command_substitution(ShellContext *ctx,
                                              const char *cmdsubst);

/* Job control functions */
static int mysh_init_job_control(ShellContext *ctx);
static void mysh_cleanup_job_control(ShellContext *ctx);
static int mysh_job_add(ShellContext *ctx, pid_t pid, const char *command);
static int mysh_job_remove(ShellContext *ctx, pid_t pid);
static int mysh_job_mark_status(ShellContext *ctx, pid_t pid, JobStatus status);
static void mysh_job_update_status(ShellContext *ctx);
static int mysh_job_foreground(ShellContext *ctx, int job_id, bool cont);
static int mysh_job_background(ShellContext *ctx, int job_id, bool cont);
static void mysh_job_print(ShellContext *ctx, int job_id);
static void mysh_job_print_all(ShellContext *ctx);

/* Builtin commands */
static int mysh_builtin_cd(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_pwd(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_exit(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_export(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_unset(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_echo(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_set(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_alias(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_unalias(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_source(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_jobs(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_fg(ShellContext *ctx, int argc, char **argv);
static int mysh_builtin_bg(ShellContext *ctx, int argc, char **argv);

/* Utility functions */
static void mysh_report_error(ShellContext *ctx, size_t line, size_t column,
                              const char *message);
static char *mysh_expand_tilde(const char *path);
static int mysh_setup_redirection(Redirection *redir);
static void mysh_restore_redirection(Redirection *redir, int saved_fd);
static bool mysh_is_builtin(const char *command);
static int mysh_find_command_path(const char *command, char *result,
                                  size_t size);
static bool mysh_is_shebang_line(const char *line);
static void mysh_handle_shebang(ShellContext *ctx);

/* Interactive shell functions */
static void mysh_interactive_loop(ShellContext *ctx);
static char **mysh_completion_callback(const char *text, int start, int end,
                                       void *userdata);
static void mysh_initialize_termline(ShellContext *ctx);
static void mysh_shutdown_termline(ShellContext *ctx);

/* Public API functions */
ShellContext *mysh_init();
void mysh_cleanup(ShellContext *ctx);
int mysh_run_string(ShellContext *ctx, const char *input);
int mysh_run_file(ShellContext *ctx, const char *filename);
int mysh_run_interactive(ShellContext *ctx);
void mysh_set_var(ShellContext *ctx, const char *name, const char *value);
char *mysh_get_var(ShellContext *ctx, const char *name);
void mysh_register_function(ShellContext *ctx, const char *name,
                            int (*func)(ShellContext *, int, char **));

/*
 * Memory Management Functions
 */

static void *mysh_malloc(size_t size) {
  void *ptr = malloc(size);
  if (!ptr && size > 0) {
    fprintf(stderr, "Fatal: Memory allocation failed for %zu bytes\n", size);
    exit(EXIT_FAILURE);
  }
  return ptr;
}

static void *mysh_realloc(void *ptr, size_t size) {
  void *new_ptr = realloc(ptr, size);
  if (!new_ptr && size > 0) {
    fprintf(stderr, "Fatal: Memory reallocation failed for %zu bytes\n", size);
    exit(EXIT_FAILURE);
  }
  return new_ptr;
}

static char *mysh_strdup(const char *str) {
  if (!str)
    return NULL;

  size_t len = strlen(str) + 1;
  char *new_str = mysh_malloc(len);
  if (new_str) {
    memcpy(new_str, str, len);
  }
  return new_str;
}

static void mysh_free(void *ptr) { free(ptr); }

/*
 * Context Management Functions
 */

static ShellContext *mysh_create_context(void) {
  ShellContext *ctx = mysh_malloc(sizeof(ShellContext));
  memset(ctx, 0, sizeof(ShellContext));

  /* Initialize mutex */
  pthread_mutex_init(&ctx->mutex, NULL);

  /* Set up global environment scope */
  ctx->global_scope = mysh_create_scope(NULL);
  ctx->current_scope = ctx->global_scope;

  /* Set default working directory */
  if (getcwd(ctx->cwd, MAX_PATH_LENGTH) == NULL) {
    strcpy(ctx->cwd, "/");
  }

  /* Initialize execution state */
  ctx->last_exit_code = 0;
  atomic_init(&ctx->is_running, false);

  /* Initialize embedding context */
  ctx->error_callback = NULL;

  /* Initialize job control */
  ctx->job_control_active = false;
  ctx->shell_pgid = getpid();
  ctx->terminal_fd = STDIN_FILENO;

  return ctx;
}

static void mysh_destroy_context(ShellContext *ctx) {
  if (!ctx)
    return;

  /* Clean up environment */
  mysh_destroy_scope(ctx->global_scope);

  /* Free functions */
  for (size_t i = 0; i < ctx->function_count; i++) {
    if (ctx->functions[i]) {
      mysh_free(ctx->functions[i]->name);
      mysh_free_node(ctx->functions[i]->body);
      mysh_free(ctx->functions[i]);
    }
  }

  /* Free aliases */
  for (size_t i = 0; i < ctx->alias_count; i++) {
    if (ctx->aliases[i]) {
      mysh_free(ctx->aliases[i]->name);
      mysh_free(ctx->aliases[i]->value);
      mysh_free(ctx->aliases[i]);
    }
  }

  /* Free current token if any */
  mysh_free_token(&ctx->current_token);

  /* Free AST if any */
  mysh_free_node(ctx->ast_root);

  /* Clean up termline if needed */
  mysh_shutdown_termline(ctx);

  /* Clean up job control */
  mysh_cleanup_job_control(ctx);

  /* Destroy mutex */
  pthread_mutex_destroy(&ctx->mutex);

  /* Finally free the context itself */
  mysh_free(ctx);
}

static void mysh_reset_context(ShellContext *ctx) {
  if (!ctx)
    return;

  /* Free current token if any */
  mysh_free_token(&ctx->current_token);

  /* Free AST if any */
  mysh_free_node(ctx->ast_root);
  ctx->ast_root = NULL;

  /* Reset input state */
  ctx->input = NULL;
  ctx->input_length = 0;
  ctx->input_pos = 0;
  ctx->input_line = 1;
  ctx->input_column = 1;

  /* Reset token */
  memset(&ctx->current_token, 0, sizeof(Token));
}

/*
 * Environment Functions
 */

static EnvScope *mysh_create_scope(EnvScope *parent) {
  EnvScope *scope = mysh_malloc(sizeof(EnvScope));

  scope->variables = mysh_malloc(sizeof(Variable *) * MAX_ENV_VARS);
  scope->var_count = 0;
  scope->var_capacity = MAX_ENV_VARS;
  scope->parent = parent;

  pthread_mutex_init(&scope->mutex, NULL);

  return scope;
}

static void mysh_destroy_scope(EnvScope *scope) {
  if (!scope)
    return;

  pthread_mutex_lock(&scope->mutex);

  /* Free variables */
  for (size_t i = 0; i < scope->var_count; i++) {
    if (scope->variables[i]) {
      mysh_free(scope->variables[i]->name);
      mysh_free(scope->variables[i]->value);
      mysh_free(scope->variables[i]);
    }
  }

  mysh_free(scope->variables);

  pthread_mutex_unlock(&scope->mutex);
  pthread_mutex_destroy(&scope->mutex);

  mysh_free(scope);
}

static Variable *mysh_get_variable(ShellContext *ctx, const char *name) {
  if (!ctx || !name)
    return NULL;

  /* Search from current scope up to global */
  EnvScope *scope = ctx->current_scope;
  while (scope) {
    pthread_mutex_lock(&scope->mutex);

    for (size_t i = 0; i < scope->var_count; i++) {
      if (strcmp(scope->variables[i]->name, name) == 0) {
        Variable *var = scope->variables[i];
        pthread_mutex_unlock(&scope->mutex);
        return var;
      }
    }

    pthread_mutex_unlock(&scope->mutex);
    scope = scope->parent;
  }

  return NULL;
}

static Variable *mysh_set_variable(ShellContext *ctx, const char *name,
                                   const char *value) {
  if (!ctx || !name)
    return NULL;

  /* First check if variable exists in current scope */
  pthread_mutex_lock(&ctx->current_scope->mutex);

  Variable *var = NULL;

  for (size_t i = 0; i < ctx->current_scope->var_count; i++) {
    if (strcmp(ctx->current_scope->variables[i]->name, name) == 0) {
      var = ctx->current_scope->variables[i];
      break;
    }
  }

  /* Create new variable if it doesn't exist */
  if (!var) {
    if (ctx->current_scope->var_count >= ctx->current_scope->var_capacity) {
      /* Increase capacity if needed */
      size_t new_capacity = ctx->current_scope->var_capacity * 2;
      ctx->current_scope->variables = mysh_realloc(
          ctx->current_scope->variables, sizeof(Variable *) * new_capacity);
      ctx->current_scope->var_capacity = new_capacity;
    }

    var = mysh_malloc(sizeof(Variable));
    var->name = mysh_strdup(name);
    var->value = value ? mysh_strdup(value) : mysh_strdup("");
    var->readonly = false;
    var->exported = false;
    atomic_init(&var->in_use, false);

    ctx->current_scope->variables[ctx->current_scope->var_count++] = var;
  } else {
    /* Check if variable is readonly */
    if (var->readonly) {
      pthread_mutex_unlock(&ctx->current_scope->mutex);
      mysh_report_error(ctx, ctx->input_line, ctx->input_column,
                        "Cannot modify readonly variable");
      return NULL;
    }

    /* Update existing variable */
    mysh_free(var->value);
    var->value = value ? mysh_strdup(value) : mysh_strdup("");
  }

  pthread_mutex_unlock(&ctx->current_scope->mutex);

  /* Update environment if exported */
  if (var->exported) {
    setenv(name, var->value, 1);
  }

  return var;
}

static void mysh_export_variable(ShellContext *ctx, const char *name) {
  if (!ctx || !name)
    return;

  Variable *var = mysh_get_variable(ctx, name);
  if (var) {
    var->exported = true;

    /* Update actual environment */
    setenv(name, var->value, 1);
  }
}

static char *mysh_expand_variable(ShellContext *ctx, const char *name) {
  if (!ctx || !name)
    return mysh_strdup("");

  Variable *var = mysh_get_variable(ctx, name);
  if (var) {
    return mysh_strdup(var->value);
  }

  /* Check environment variables */
  const char *env_value = getenv(name);
  if (env_value) {
    return mysh_strdup(env_value);
  }

  /* Variable not found */
  return mysh_strdup("");
}

static Function *mysh_get_function(ShellContext *ctx, const char *name) {
  if (!ctx || !name)
    return NULL;

  pthread_mutex_lock(&ctx->mutex);

  for (size_t i = 0; i < ctx->function_count; i++) {
    if (strcmp(ctx->functions[i]->name, name) == 0) {
      Function *func = ctx->functions[i];
      pthread_mutex_unlock(&ctx->mutex);
      return func;
    }
  }

  pthread_mutex_unlock(&ctx->mutex);
  return NULL;
}

static Function *mysh_set_function(ShellContext *ctx, const char *name,
                                   Node *body) {
  if (!ctx || !name || !body)
    return NULL;

  pthread_mutex_lock(&ctx->mutex);

  /* Check if function already exists */
  Function *func = NULL;
  for (size_t i = 0; i < ctx->function_count; i++) {
    if (strcmp(ctx->functions[i]->name, name) == 0) {
      func = ctx->functions[i];
      break;
    }
  }

  if (func) {
    /* Replace existing function */
    mysh_free_node(func->body);
    func->body = body;
    pthread_mutex_unlock(&ctx->mutex);
    return func;
  }

  /* Create new function */
  if (ctx->function_count >= MAX_FUNCTIONS) {
    pthread_mutex_unlock(&ctx->mutex);
    mysh_report_error(ctx, ctx->input_line, ctx->input_column,
                      "Maximum number of functions reached");
    return NULL;
  }

  func = mysh_malloc(sizeof(Function));
  func->name = mysh_strdup(name);
  func->body = body;
  atomic_init(&func->in_use, false);

  ctx->functions[ctx->function_count++] = func;

  pthread_mutex_unlock(&ctx->mutex);
  return func;
}

static Alias *mysh_get_alias(ShellContext *ctx, const char *name) {
  if (!ctx || !name)
    return NULL;

  pthread_mutex_lock(&ctx->mutex);

  for (size_t i = 0; i < ctx->alias_count; i++) {
    if (strcmp(ctx->aliases[i]->name, name) == 0) {
      Alias *alias = ctx->aliases[i];
      pthread_mutex_unlock(&ctx->mutex);
      return alias;
    }
  }

  pthread_mutex_unlock(&ctx->mutex);
  return NULL;
}

static Alias *mysh_set_alias(ShellContext *ctx, const char *name,
                             const char *value) {
  if (!ctx || !name || !value)
    return NULL;

  pthread_mutex_lock(&ctx->mutex);

  /* Check if alias already exists */
  Alias *alias = NULL;
  for (size_t i = 0; i < ctx->alias_count; i++) {
    if (strcmp(ctx->aliases[i]->name, name) == 0) {
      alias = ctx->aliases[i];
      break;
    }
  }

  if (alias) {
    /* Replace existing alias */
    mysh_free(alias->value);
    alias->value = mysh_strdup(value);
    pthread_mutex_unlock(&ctx->mutex);
    return alias;
  }

  /* Create new alias */
  if (ctx->alias_count >= MAX_ALIASES) {
    pthread_mutex_unlock(&ctx->mutex);
    mysh_report_error(ctx, ctx->input_line, ctx->input_column,
                      "Maximum number of aliases reached");
    return NULL;
  }

  alias = mysh_malloc(sizeof(Alias));
  alias->name = mysh_strdup(name);
  alias->value = mysh_strdup(value);
  atomic_init(&alias->in_use, false);

  ctx->aliases[ctx->alias_count++] = alias;

  pthread_mutex_unlock(&ctx->mutex);
  return alias;
}

static void mysh_push_scope(ShellContext *ctx) {
  if (!ctx)
    return;

  EnvScope *new_scope = mysh_create_scope(ctx->current_scope);
  ctx->current_scope = new_scope;
}

static void mysh_pop_scope(ShellContext *ctx) {
  if (!ctx || ctx->current_scope == ctx->global_scope)
    return;

  EnvScope *old_scope = ctx->current_scope;
  ctx->current_scope = old_scope->parent;
  mysh_destroy_scope(old_scope);
}

/*
 * Lexer Functions
 */

static void mysh_init_lexer(ShellContext *ctx, const char *input) {
  if (!ctx || !input)
    return;

  ctx->input = (char *)input;
  ctx->input_length = strlen(input);
  ctx->input_pos = 0;
  ctx->input_line = 1;
  ctx->input_column = 1;

  /* Skip shebang line if present */
  mysh_handle_shebang(ctx);

  /* Initialize the first token */
  ctx->current_token = mysh_scan_token(ctx);
}

static char mysh_peek_char(ShellContext *ctx) {
  if (!ctx || ctx->input_pos >= ctx->input_length)
    return '\0';
  return ctx->input[ctx->input_pos];
}

static char mysh_advance_char(ShellContext *ctx) {
  if (!ctx || ctx->input_pos >= ctx->input_length)
    return '\0';

  char c = ctx->input[ctx->input_pos++];

  if (c == '\n') {
    ctx->input_line++;
    ctx->input_column = 1;
  } else {
    ctx->input_column++;
  }

  return c;
}

static bool mysh_is_at_end(ShellContext *ctx) {
  return !ctx || ctx->input_pos >= ctx->input_length;
}

static void mysh_skip_whitespace(ShellContext *ctx) {
  if (!ctx)
    return;

  while (!mysh_is_at_end(ctx)) {
    char c = mysh_peek_char(ctx);

    if (c == ' ' || c == '\t' || c == '\r') {
      mysh_advance_char(ctx);
    } else {
      break;
    }
  }
}

static Token mysh_scan_token(ShellContext *ctx) {
  if (!ctx) {
    Token token = {TOKEN_ERROR, NULL, 0, 0, 0, {.op = OP_NONE}};
    return token;
  }

  mysh_skip_whitespace(ctx);

  if (mysh_is_at_end(ctx)) {
    Token token = {TOKEN_EOF,         NULL,           0, ctx->input_line,
                   ctx->input_column, {.op = OP_NONE}};
    return token;
  }

  char c = mysh_peek_char(ctx);

  /* Comments */
  if (c == '#') {
    return mysh_scan_comment(ctx);
  }

  /* Newline */
  if (c == '\n') {
    mysh_advance_char(ctx);
    Token token = {TOKEN_NEWLINE,     NULL,           0, ctx->input_line - 1,
                   ctx->input_column, {.op = OP_NONE}};
    return token;
  }

  /* Variable */
  if (c == '$') {
    /* Check for command substitution $(...) */
    if (ctx->input_pos + 1 < ctx->input_length &&
        ctx->input[ctx->input_pos + 1] == '(') {
      return mysh_scan_cmdsubst(ctx);
    }
    return mysh_scan_variable(ctx);
  }

  /* Command substitution */
  if (c == '`') {
    return mysh_scan_cmdsubst(ctx);
  }

  /* Operators */
  if (c == '|' || c == '&' || c == ';' || c == '(' || c == ')' || c == '{' ||
      c == '}') {
    return mysh_scan_operator(ctx);
  }

  /* Redirections */
  if (c == '<' || c == '>') {
    return mysh_scan_redirect(ctx);
  }

  /* Word (command, argument, etc.) */
  return mysh_scan_word(ctx);
}

static Token mysh_scan_word(ShellContext *ctx) {
  size_t start_line = ctx->input_line;
  size_t start_column = ctx->input_column;
  size_t start = ctx->input_pos;
  bool in_quotes = false;
  char quote_char = '\0';

  /* Buffer for constructing the word with expansions */
  char *expanded_word = mysh_malloc(MAX_TOKEN_LENGTH);
  size_t expanded_pos = 0;
  expanded_word[0] = '\0';

  /* Scan until we hit end, whitespace, or special character outside quotes */
  while (!mysh_is_at_end(ctx)) {
    char c = mysh_peek_char(ctx);

    /* Handle quotes */
    if (c == '\'' || c == '"') {
      if (!in_quotes) {
        /* Start of quoted section */
        in_quotes = true;
        quote_char = c;
        mysh_advance_char(ctx);
        continue;
      } else if (c == quote_char) {
        /* End of quoted section */
        in_quotes = false;
        mysh_advance_char(ctx);
        continue;
      }
    }

    /* Handle command substitution inside double quotes */
    if (in_quotes && quote_char == '"' && c == '$' &&
        ctx->input_pos + 1 < ctx->input_length && ctx->input[ctx->input_pos + 1] == '(') {

      /* Get command substitution token */
      Token subst_token = mysh_scan_cmdsubst(ctx);

      /* Extract command without markers */
      char *cmd_content = NULL;
      if (subst_token.value[0] == '$' && subst_token.value[1] == '(' &&
          subst_token.value[strlen(subst_token.value) - 1] == ')') {
        cmd_content = mysh_strdup(subst_token.value + 2);
        cmd_content[strlen(cmd_content) - 1] = '\0';
      } else {
        cmd_content = mysh_strdup(subst_token.value);
      }

      /* Execute command and get output */
      char *output = mysh_expand_command_substitution(ctx, cmd_content);
      mysh_free(cmd_content);

      /* Append output to expanded word */
      size_t output_len = strlen(output);
      if (expanded_pos + output_len < MAX_TOKEN_LENGTH) {
        strcpy(expanded_word + expanded_pos, output);
        expanded_pos += output_len;
      }

      mysh_free(output);
      mysh_free_token(&subst_token);
      continue;
    }

    /* Handle command substitution with backticks inside double quotes */
    if (in_quotes && quote_char == '"' && c == '`') {
      /* Get command substitution token */
      Token subst_token = mysh_scan_cmdsubst(ctx);

      /* Extract command without markers */
      char *cmd_content = NULL;
      if (subst_token.value[0] == '`' && subst_token.value[strlen(subst_token.value) - 1] == '`') {
        cmd_content = mysh_strdup(subst_token.value + 1);
        cmd_content[strlen(cmd_content) - 1] = '\0';
      } else {
        cmd_content = mysh_strdup(subst_token.value);
      }

      /* Execute command and get output */
      char *output = mysh_expand_command_substitution(ctx, cmd_content);
      mysh_free(cmd_content);

      /* Append output to expanded word */
      size_t output_len = strlen(output);
      if (expanded_pos + output_len < MAX_TOKEN_LENGTH) {
        strcpy(expanded_word + expanded_pos, output);
        expanded_pos += output_len;
      }

      mysh_free(output);
      mysh_free_token(&subst_token);
      continue;
    }

    /* If in quotes, keep going until matching quote */
    if (in_quotes) {
      /* Add character to expanded word */
      if (expanded_pos < MAX_TOKEN_LENGTH - 1) {
        expanded_word[expanded_pos++] = c;
        expanded_word[expanded_pos] = '\0';
      }
      mysh_advance_char(ctx);
      continue;
    }

    /* Break on space, newline, or special characters when not in quotes */
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '|' ||
        c == '&' || c == ';' || c == '(' || c == ')' || c == '{' || c == '}' ||
        c == '<' || c == '>' || c == '$' || c == '`' || c == '#') {
      break;
    }

    /* Add character to expanded word */
    if (expanded_pos < MAX_TOKEN_LENGTH - 1) {
      expanded_word[expanded_pos++] = c;
      expanded_word[expanded_pos] = '\0';
    }
    mysh_advance_char(ctx);
  }

  /* Create token */
  char *value;

  if (expanded_pos > 0) {
    /* Use the expanded word */
    value = mysh_strdup(expanded_word);
  } else {
    /* No expansions, use original text */
    size_t length = ctx->input_pos - start;
    value = mysh_malloc(length + 1);
    memcpy(value, ctx->input + start, length);
    value[length] = '\0';
  }

  mysh_free(expanded_word);

  Token token = {TOKEN_WORD, value, strlen(value), start_line, start_column, {.op = OP_NONE}};
  return token;
}

static Token mysh_scan_operator(ShellContext *ctx) {
  size_t start_line = ctx->input_line;
  size_t start_column = ctx->input_column;

  /* Get the first character */
  char c = mysh_advance_char(ctx);

  /* Create token */
  char *value = mysh_malloc(3); /* Maximum operator length is 2 + null */
  value[0] = c;

  OperatorType op = OP_NONE;

  /* Check for two-character operators */
  if (c == '|' && mysh_peek_char(ctx) == '|') {
    value[1] = mysh_advance_char(ctx);
    value[2] = '\0';
    op = OP_OR;
  } else if (c == '&' && mysh_peek_char(ctx) == '&') {
    value[1] = mysh_advance_char(ctx);
    value[2] = '\0';
    op = OP_AND;
  } else {
    value[1] = '\0';

    /* Single character operators */
    switch (c) {
    case '|':
      op = OP_PIPE;
      break;
    case '&':
      op = OP_BACKGROUND;
      break;
    case ';':
      op = OP_SEMICOLON;
      break;
    case '(':
      op = OP_LPAREN;
      break;
    case ')':
      op = OP_RPAREN;
      break;
    case '{':
      op = OP_LBRACE;
      break;
    case '}':
      op = OP_RBRACE;
      break;
    default:
      op = OP_NONE;
      break;
    }
  }

  Token token = {TOKEN_OPERATOR, value,        strlen(value),
                 start_line,     start_column, {.op = op}};
  return token;
}

static Token mysh_scan_redirect(ShellContext *ctx) {
  size_t start_line = ctx->input_line;
  size_t start_column = ctx->input_column;

  /* Get the first character */
  char c = mysh_advance_char(ctx);

  /* Create token */
  char *value = mysh_malloc(3); /* Maximum redirect length is 2 + null */
  value[0] = c;

  RedirectionType redir = REDIR_NONE;

  /* Check for two-character redirections */
  if (c == '>' && mysh_peek_char(ctx) == '>') {
    value[1] = mysh_advance_char(ctx);
    value[2] = '\0';
    redir = REDIR_APPEND;
  } else if (c == '<' && mysh_peek_char(ctx) == '<') {
    value[1] = mysh_advance_char(ctx);
    value[2] = '\0';
    redir = REDIR_HEREDOC;
  } else if (c == '>' && mysh_peek_char(ctx) == '&') {
    value[1] = mysh_advance_char(ctx);
    value[2] = '\0';
    redir = REDIR_DUPFD;
  } else {
    value[1] = '\0';

    /* Single character redirections */
    switch (c) {
    case '>':
      redir = REDIR_OUT;
      break;
    case '<':
      redir = REDIR_IN;
      break;
    default:
      redir = REDIR_NONE;
      break;
    }
  }

  Token token = {TOKEN_REDIRECT, value,        strlen(value),
                 start_line,     start_column, {.redir = redir}};
  return token;
}

static Token mysh_scan_variable(ShellContext *ctx) {
  size_t start_line = ctx->input_line;
  size_t start_column = ctx->input_column;
  size_t start = ctx->input_pos;

  /* Skip the $ */
  mysh_advance_char(ctx);

  /* Check for ${...} format */
  bool has_braces = false;
  if (!mysh_is_at_end(ctx) && mysh_peek_char(ctx) == '{') {
    has_braces = true;
    mysh_advance_char(ctx);
  }

  if (has_braces) {
    /* Scan until closing brace */
    while (!mysh_is_at_end(ctx) && mysh_peek_char(ctx) != '}') {
      mysh_advance_char(ctx);
    }

    /* Skip closing brace */
    if (!mysh_is_at_end(ctx)) {
      mysh_advance_char(ctx);
    }
  } else {
    /* Scan valid variable name characters */
    if (!mysh_is_at_end(ctx) &&
        (isalpha(mysh_peek_char(ctx)) || mysh_peek_char(ctx) == '_')) {
      mysh_advance_char(ctx);

      while (!mysh_is_at_end(ctx) &&
             (isalnum(mysh_peek_char(ctx)) || mysh_peek_char(ctx) == '_')) {
        mysh_advance_char(ctx);
      }
    } else if (!mysh_is_at_end(ctx) &&
               (isdigit(mysh_peek_char(ctx)) || mysh_peek_char(ctx) == '@' ||
                mysh_peek_char(ctx) == '*' || mysh_peek_char(ctx) == '#' ||
                mysh_peek_char(ctx) == '?' || mysh_peek_char(ctx) == '-' ||
                mysh_peek_char(ctx) == '$' || mysh_peek_char(ctx) == '!')) {
      /* Special variables ($1, $@, $*, $#, $?, $-, $$, $!) */
      mysh_advance_char(ctx);
    }
  }

  /* Create token */
  size_t length = ctx->input_pos - start;
  char *value = mysh_malloc(length + 1);
  memcpy(value, ctx->input + start, length);
  value[length] = '\0';

  Token token = {TOKEN_VARIABLE, value,        length,
                 start_line,     start_column, {.op = OP_NONE}};
  return token;
}

static Token mysh_scan_cmdsubst(ShellContext *ctx) {
  size_t start_line = ctx->input_line;
  size_t start_column = ctx->input_column;
  size_t start = ctx->input_pos;

  /* Determine type of command substitution: $(...) or `...` */
  bool is_dollar_paren = (mysh_peek_char(ctx) == '$');

  /* Skip the opening marker */
  mysh_advance_char(ctx); /* Skip $ or ` */
  if (is_dollar_paren) {
    mysh_advance_char(ctx); /* Skip ( */
  }

  /* Track nested parentheses for $(...)*/
  int nesting = is_dollar_paren ? 1 : 0;
  bool in_quotes = false;
  char quote_char = '\0';

  /* Scan until closing marker */
  while (!mysh_is_at_end(ctx)) {
    char c = mysh_peek_char(ctx);

    /* Handle quotes */
    if (c == '\'' || c == '"') {
      if (!in_quotes) {
        in_quotes = true;
        quote_char = c;
      } else if (c == quote_char) {
        in_quotes = false;
      }
      mysh_advance_char(ctx);
      continue;
    }

    /* Skip escaped characters in quoted strings */
    if (in_quotes && c == '\\') {
      mysh_advance_char(ctx); /* Skip the backslash */
      if (!mysh_is_at_end(ctx)) {
        mysh_advance_char(ctx); /* Skip the escaped character */
      }
      continue;
    }

    /* Handle nesting for $(...) */
    if (is_dollar_paren && !in_quotes) {
      if (c == '(' && ctx->input_pos > 0 &&
          ctx->input[ctx->input_pos - 1] == '$') {
        nesting++;
      } else if (c == ')') {
        nesting--;
        if (nesting == 0) {
          mysh_advance_char(ctx); /* Skip closing ) */
          break;
        }
      }
    } else if (!is_dollar_paren && c == '`' && !in_quotes) {
      mysh_advance_char(ctx); /* Skip closing ` */
      break;
    }

    mysh_advance_char(ctx);
  }

  /* Create token */
  size_t length = ctx->input_pos - start;
  char *value = mysh_malloc(length + 1);
  memcpy(value, ctx->input + start, length);
  value[length] = '\0';

  Token token = {TOKEN_CMDSUBST, value,        length,
                 start_line,     start_column, {.op = OP_NONE}};
  return token;
}

static Token mysh_scan_comment(ShellContext *ctx) {
  size_t start_line = ctx->input_line;
  size_t start_column = ctx->input_column;
  size_t start = ctx->input_pos;

  /* Skip # character */
  mysh_advance_char(ctx);

  /* Read until end of line */
  while (!mysh_is_at_end(ctx) && mysh_peek_char(ctx) != '\n') {
    mysh_advance_char(ctx);
  }

  /* Create token */
  size_t length = ctx->input_pos - start;
  char *value = mysh_malloc(length + 1);
  memcpy(value, ctx->input + start, length);
  value[length] = '\0';

  Token token = {TOKEN_COMMENT, value,        length,
                 start_line,    start_column, {.op = OP_NONE}};
  return token;
}

static void mysh_free_token(Token *token) {
  if (!token)
    return;

  if (token->value) {
    mysh_free(token->value);
    token->value = NULL;
  }

  token->length = 0;
}

/*
 * Parser Functions
 */

static void mysh_init_parser(ShellContext *ctx) {
  if (!ctx)
    return;

  /* Free any previous AST */
  if (ctx->ast_root) {
    mysh_free_node(ctx->ast_root);
    ctx->ast_root = NULL;
  }
}

static Token mysh_current_token(ShellContext *ctx) {
  return ctx->current_token;
}

static Token mysh_advance_token(ShellContext *ctx) {
  Token old_token = ctx->current_token;
  ctx->current_token = mysh_scan_token(ctx);

  /* Skip comment tokens */
  while (ctx->current_token.type == TOKEN_COMMENT) {
    mysh_free_token(&ctx->current_token);
    ctx->current_token = mysh_scan_token(ctx);
  }

  return old_token;
}

static bool mysh_check_token(ShellContext *ctx, TokenType type) {
  return ctx->current_token.type == type;
}

static bool mysh_match_token(ShellContext *ctx, TokenType type) {
  if (mysh_check_token(ctx, type)) {
    mysh_advance_token(ctx);
    return true;
  }
  return false;
}

static Node *mysh_parse(ShellContext *ctx) {
  if (!ctx)
    return NULL;

  mysh_init_parser(ctx);

  Node *node = NULL;
  Node *current = NULL;

  /* Parse multiple commands separated by newlines */
  while (!mysh_check_token(ctx, TOKEN_EOF)) {
    /* Skip empty lines */
    while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
      /* Just skip */
    }

    if (mysh_check_token(ctx, TOKEN_EOF)) {
      break;
    }

    Node *command = mysh_parse_list(ctx);
    if (!command) {
      /* Syntax error - clean up and return */
      mysh_free_node(node);
      return NULL;
    }

    /* Add to the list */
    if (!node) {
      node = command;
      current = command;
    } else {
      current->next = command;
      current = command;
    }

    /* Handle semicolon or newline as command separator */
    if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
        ctx->current_token.op == OP_SEMICOLON) {
      mysh_advance_token(ctx);
    } else if (mysh_check_token(ctx, TOKEN_NEWLINE)) {
      mysh_advance_token(ctx);
    }
  }

  /* Store the AST root */
  ctx->ast_root = node;

  return node;
}

static Node *mysh_parse_list(ShellContext *ctx) {
  if (!ctx)
    return NULL;

  Node *pipeline = mysh_parse_pipeline(ctx);
  if (!pipeline)
    return NULL;

  /* Check for list operators: ; && || */
  if (mysh_check_token(ctx, TOKEN_OPERATOR)) {
    OperatorType op = ctx->current_token.op;

    if (op == OP_SEMICOLON || op == OP_AND || op == OP_OR) {
      mysh_advance_token(ctx);

      /* Allow for optional newline after operator */
      while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
        /* Just skip newlines */
      }

      Node *right = mysh_parse_list(ctx);
      if (!right) {
        mysh_free_node(pipeline);
        return NULL;
      }

      /* Create a list node */
      Node *list_node = mysh_malloc(sizeof(Node));
      list_node->type = NODE_LIST;
      list_node->next = NULL;

      ListNode *list = mysh_malloc(sizeof(ListNode));
      list->commands = mysh_malloc(sizeof(Node *) * 2);
      list->commands[0] = pipeline;
      list->commands[1] = right;
      list->command_count = 2;
      list->operators = mysh_malloc(sizeof(OperatorType));
      list->operators[0] = op;

      list_node->list = list;

      return list_node;
    }
  }

  /* Just a single pipeline */
  return pipeline;
}

static Node *mysh_parse_pipeline(ShellContext *ctx) {
  if (!ctx)
    return NULL;

  Node *command = mysh_parse_command(ctx);
  if (!command)
    return NULL;

  /* Check for pipeline operator | */
  if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
      ctx->current_token.op == OP_PIPE) {
    mysh_advance_token(ctx);

    /* Allow for optional newline after pipe */
    while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
      /* Just skip newlines */
    }

    Node *right = mysh_parse_pipeline(ctx);
    if (!right) {
      mysh_free_node(command);
      return NULL;
    }

    /* Create a pipeline node */
    Node *pipeline_node = mysh_malloc(sizeof(Node));
    pipeline_node->type = NODE_PIPELINE;
    pipeline_node->next = NULL;

    /* Count commands in the pipeline */
    size_t command_count = 1;
    if (right->type == NODE_PIPELINE) {
      command_count += right->pipeline->command_count;
    } else {
      command_count++;
    }

    PipelineNode *pipeline = mysh_malloc(sizeof(PipelineNode));
    pipeline->commands = mysh_malloc(sizeof(Node *) * command_count);
    pipeline->command_count = command_count;
    pipeline->background = false;

    /* Add the left command */
    pipeline->commands[0] = command;

    /* Add the right commands */
    if (right->type == NODE_PIPELINE) {
      for (size_t i = 0; i < right->pipeline->command_count; i++) {
        pipeline->commands[i + 1] = right->pipeline->commands[i];
      }

      /* Clean up the right pipeline, but don't free its commands */
      Node *temp = right;
      right->pipeline->command_count = 0;
      mysh_free(right->pipeline->commands);
      mysh_free(right->pipeline);
      mysh_free(temp);
    } else {
      pipeline->commands[1] = right;
    }

    pipeline_node->pipeline = pipeline;

    /* Check for background operator & */
    if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
        ctx->current_token.op == OP_BACKGROUND) {
      mysh_advance_token(ctx);
      pipeline->background = true;
    }

    return pipeline_node;
  }

  /* Check for background operator & */
  if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
      ctx->current_token.op == OP_BACKGROUND) {
    mysh_advance_token(ctx);

    if (command->type == NODE_COMMAND) {
      command->command->background = true;
    }
  }

  /* Just a single command */
  return command;
}

static Node *mysh_parse_command(ShellContext *ctx) {
  /* Check for special command forms first */
  if (mysh_check_token(ctx, TOKEN_WORD)) {
    /* Look ahead for special commands */
    const char *word = ctx->current_token.value;

    if (strcmp(word, "if") == 0) {
      return mysh_parse_if(ctx);
    } else if (strcmp(word, "while") == 0 || strcmp(word, "until") == 0) {
      return mysh_parse_while(ctx);
    } else if (strcmp(word, "for") == 0) {
      return mysh_parse_for(ctx);
    } else if (strcmp(word, "function") == 0) {
      return mysh_parse_function(ctx);
    }
  }

  /* Check for subshell */
  if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
      ctx->current_token.op == OP_LPAREN) {
    return mysh_parse_subshell(ctx);
  }

  /* Check for command substitution */
  if (mysh_check_token(ctx, TOKEN_CMDSUBST)) {
    return mysh_parse_cmdsubst(ctx);
  }

  /* Check for variable assignment */
  if (mysh_check_token(ctx, TOKEN_WORD)) {
    const char *word = ctx->current_token.value;
    bool is_assignment = false;

    /* Check if it's a valid assignment format (name=value) */
    for (size_t i = 0; i < strlen(word); i++) {
      if (word[i] == '=') {
        is_assignment = true;
        break;
      }
    }

    if (is_assignment) {
      return mysh_parse_assignment(ctx);
    }
  }

  /* Regular command */
  if (!mysh_check_token(ctx, TOKEN_WORD)) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected command name");
    return NULL;
  }

  char *name = mysh_strdup(ctx->current_token.value);
  mysh_advance_token(ctx);

  /* Create command node */
  Node *command_node = mysh_malloc(sizeof(Node));
  command_node->type = NODE_COMMAND;
  command_node->next = NULL;

  CommandNode *command = mysh_malloc(sizeof(CommandNode));
  command->name = name;
  command->args = mysh_malloc(sizeof(char *) * MAX_ARGS);
  command->args[0] = mysh_strdup(name); /* First arg is command name */
  command->arg_count = 1;
  command->redirections = NULL;
  command->redir_count = 0;
  command->background = false;

  command_node->command = command;

  /* Parse arguments and redirections */
  size_t redir_capacity = 0;

  while (mysh_check_token(ctx, TOKEN_WORD) ||
         mysh_check_token(ctx, TOKEN_REDIRECT) ||
         mysh_check_token(ctx, TOKEN_VARIABLE) ||
         mysh_check_token(ctx, TOKEN_CMDSUBST)) {

    if (mysh_check_token(ctx, TOKEN_REDIRECT)) {
      /* Redirection */
      Token redir_token = mysh_current_token(ctx);
      RedirectionType redir_type = redir_token.redir;
      mysh_advance_token(ctx);

      /* Get the target */
      if (!mysh_check_token(ctx, TOKEN_WORD) &&
          !mysh_check_token(ctx, TOKEN_VARIABLE)) {
        mysh_report_error(ctx, ctx->current_token.line,
                          ctx->current_token.column,
                          "Expected redirection target");
        mysh_free_node(command_node);
        return NULL;
      }

      Token target_token = mysh_current_token(ctx);
      char *target = mysh_strdup(target_token.value);
      mysh_advance_token(ctx);

      /* Add redirection */
      if (command->redir_count >= redir_capacity) {
        size_t new_capacity = redir_capacity == 0 ? 4 : redir_capacity * 2;
        command->redirections = mysh_realloc(
            command->redirections, sizeof(Redirection) * new_capacity);
        redir_capacity = new_capacity;
      }

      Redirection *redir = &command->redirections[command->redir_count++];
      redir->type = redir_type;

      /* Set appropriate file descriptor based on type */
      if (redir_type == REDIR_IN) {
        redir->fd = STDIN_FILENO; /* 0 for input */
      } else {
        redir->fd = STDOUT_FILENO; /* 1 for output */
      }

      redir->target = target;
      redir->close_after = true;
    } else if (mysh_check_token(ctx, TOKEN_VARIABLE)) {
      /* Variable expansion */
      Token var_token = mysh_current_token(ctx);
      char *var_name;

      /* Extract variable name without $ sign */
      if (var_token.value[0] == '$') {
        var_name = var_token.value + 1;

        /* Handle ${...} format */
        if (var_name[0] == '{' && strlen(var_name) > 2 &&
            var_name[strlen(var_name) - 1] == '}') {
          var_name = mysh_strdup(var_name + 1);
          var_name[strlen(var_name) - 1] = '\0';
          char *expanded = mysh_expand_variable(ctx, var_name);
          mysh_free(var_name);
          var_name = expanded;
        } else {
          var_name = mysh_expand_variable(ctx, var_name);
        }
      } else {
        var_name = mysh_strdup(var_token.value);
      }

      /* Add as argument */
      if (command->arg_count < MAX_ARGS) {
        command->args[command->arg_count++] = var_name;
      } else {
        mysh_free(var_name);
        mysh_report_error(ctx, var_token.line, var_token.column,
                          "Too many arguments");
      }

      mysh_advance_token(ctx);
    } else if (mysh_check_token(ctx, TOKEN_CMDSUBST)) {
      /* Command substitution */
      Token cmdsubst_token = mysh_current_token(ctx);

      /* Extract command without markers */
      char *cmd_str = cmdsubst_token.value;
      char *cmd_content = NULL;

      if (cmd_str[0] == '$' && cmd_str[1] == '(' &&
          cmd_str[strlen(cmd_str) - 1] == ')') {
        /* $(...) format */
        cmd_content = mysh_strdup(cmd_str + 2);
        cmd_content[strlen(cmd_content) - 1] = '\0';
      } else if (cmd_str[0] == '`' && cmd_str[strlen(cmd_str) - 1] == '`') {
        /* `...` format */
        cmd_content = mysh_strdup(cmd_str + 1);
        cmd_content[strlen(cmd_content) - 1] = '\0';
      } else {
        /* Shouldn't get here, but just in case */
        cmd_content = mysh_strdup(cmd_str);
      }

      /* Execute command and get output */
      char *output = mysh_expand_command_substitution(ctx, cmd_content);
      mysh_free(cmd_content);

      /* Add as argument */
      if (command->arg_count < MAX_ARGS) {
        command->args[command->arg_count++] = output;
      } else {
        mysh_free(output);
        mysh_report_error(ctx, cmdsubst_token.line, cmdsubst_token.column,
                          "Too many arguments");
      }

      mysh_advance_token(ctx);
    } else {
      /* Regular argument */
      Token arg_token = mysh_current_token(ctx);

      if (command->arg_count < MAX_ARGS) {
        command->args[command->arg_count++] = mysh_strdup(arg_token.value);
      } else {
        mysh_report_error(ctx, arg_token.line, arg_token.column,
                          "Too many arguments");
      }

      mysh_advance_token(ctx);
    }
  }

  /* Null-terminate args array */
  command->args[command->arg_count] = NULL;

  return command_node;
}

static Node *mysh_parse_assignment(ShellContext *ctx) {
  if (!mysh_check_token(ctx, TOKEN_WORD)) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected variable assignment");
    return NULL;
  }

  Token token = mysh_current_token(ctx);
  const char *word = token.value;

  /* Split at the equals sign */
  char *equals = strchr(word, '=');
  if (!equals) {
    mysh_report_error(ctx, token.line, token.column,
                      "Invalid variable assignment format");
    return NULL;
  }

  /* Extract name and value */
  size_t name_len = equals - word;
  char *name = mysh_malloc(name_len + 1);
  strncpy(name, word, name_len);
  name[name_len] = '\0';

  /* Value starts after the equals sign */
  char *value = mysh_strdup(equals + 1);

  /* Create assignment node */
  Node *assign_node = mysh_malloc(sizeof(Node));
  assign_node->type = NODE_ASSIGNMENT;
  assign_node->next = NULL;

  AssignmentNode *assign = mysh_malloc(sizeof(AssignmentNode));
  assign->name = name;
  assign->value = value;
  assign->export = false;

  assign_node->assignment = assign;

  /* Consume the token */
  mysh_advance_token(ctx);

  return assign_node;
}

static Node *mysh_parse_if(ShellContext *ctx) {
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "if") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'if' keyword");
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Parse condition up to semicolon */
  Node *condition = mysh_parse_pipeline(ctx);
  if (!condition) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected condition after 'if'");
    return NULL;
  }

  /* Check for semicolon */
  if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
      ctx->current_token.op == OP_SEMICOLON) {
    mysh_advance_token(ctx);
  }

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Expect 'then' keyword */
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "then") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'then' after condition");
    mysh_free_node(condition);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Parse 'then' body */
  Node *then_part = mysh_parse_list(ctx);
  if (!then_part) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected commands after 'then'");
    mysh_free_node(condition);
    return NULL;
  }

  Node *else_part = NULL;

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Check for 'else' or 'elif' */
  if (mysh_check_token(ctx, TOKEN_WORD)) {
    if (strcmp(ctx->current_token.value, "else") == 0) {
      mysh_advance_token(ctx);

      /* Skip newlines */
      while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
        /* Just skip */
      }

      else_part = mysh_parse_list(ctx);
      if (!else_part) {
        mysh_report_error(ctx, ctx->current_token.line,
                          ctx->current_token.column,
                          "Expected commands after 'else'");
        mysh_free_node(condition);
        mysh_free_node(then_part);
        return NULL;
      }
    } else if (strcmp(ctx->current_token.value, "elif") == 0) {
      /* Treat 'elif' as a nested 'if' in the 'else' branch */
      else_part = mysh_parse_if(ctx);
      if (!else_part) {
        mysh_free_node(condition);
        mysh_free_node(then_part);
        return NULL;
      }
    }
  }

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Expect 'fi' keyword */
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "fi") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'fi' to end if statement");
    mysh_free_node(condition);
    mysh_free_node(then_part);
    if (else_part)
      mysh_free_node(else_part);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Create if node */
  Node *if_node = mysh_malloc(sizeof(Node));
  if_node->type = NODE_IF;
  if_node->next = NULL;

  IfNode *if_struct = mysh_malloc(sizeof(IfNode));
  if_struct->condition = condition;
  if_struct->then_part = then_part;
  if_struct->else_part = else_part;

  if_node->if_node = if_struct;

  return if_node;
}

static Node *mysh_parse_while(ShellContext *ctx) {
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      (strcmp(ctx->current_token.value, "while") != 0 &&
       strcmp(ctx->current_token.value, "until") != 0)) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'while' or 'until' keyword");
    return NULL;
  }

  bool is_until = strcmp(ctx->current_token.value, "until") == 0;

  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Parse condition */
  Node *condition = mysh_parse_pipeline(ctx);
  if (!condition) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected condition after 'while'/'until'");
    return NULL;
  }

  /* Check for semicolon */
  if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
      ctx->current_token.op == OP_SEMICOLON) {
    mysh_advance_token(ctx);
  }

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Expect 'do' keyword */
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "do") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'do' after condition");
    mysh_free_node(condition);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Parse loop body */
  Node *body = mysh_parse_list(ctx);
  if (!body) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected commands after 'do'");
    mysh_free_node(condition);
    return NULL;
  }

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Expect 'done' keyword */
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "done") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'done' to end loop");
    mysh_free_node(condition);
    mysh_free_node(body);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Create while node */
  Node *while_node = mysh_malloc(sizeof(Node));
  while_node->type = NODE_WHILE;
  while_node->next = NULL;

  WhileNode *while_struct = mysh_malloc(sizeof(WhileNode));
  while_struct->condition = condition;
  while_struct->body = body;
  while_struct->until = is_until;

  while_node->while_node = while_struct;

  return while_node;
}

static Node *mysh_parse_for(ShellContext *ctx) {
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "for") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'for' keyword");
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Parse variable name */
  if (!mysh_check_token(ctx, TOKEN_WORD)) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected variable name after 'for'");
    return NULL;
  }

  char *var_name = mysh_strdup(ctx->current_token.value);
  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Expect 'in' keyword */
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "in") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'in' after variable name");
    mysh_free(var_name);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Parse word list */
  char **words = mysh_malloc(sizeof(char *) * MAX_ARGS);
  size_t word_count = 0;

  while (mysh_check_token(ctx, TOKEN_WORD) ||
         mysh_check_token(ctx, TOKEN_VARIABLE) ||
         mysh_check_token(ctx, TOKEN_CMDSUBST) ||
         mysh_check_token(ctx, TOKEN_NEWLINE)) {

    /* Skip newlines between words */
    if (mysh_check_token(ctx, TOKEN_NEWLINE)) {
      mysh_advance_token(ctx);
      continue;
    }

    if (word_count < MAX_ARGS) {
      if (mysh_check_token(ctx, TOKEN_WORD)) {
        words[word_count++] = mysh_strdup(ctx->current_token.value);
      } else if (mysh_check_token(ctx, TOKEN_VARIABLE)) {
        /* Extract variable name without $ sign */
        char *var_name = ctx->current_token.value + 1;

        /* Handle ${...} format */
        if (var_name[0] == '{' && var_name[strlen(var_name) - 1] == '}') {
          /* Create a temporary copy to modify */
          char *temp = mysh_strdup(var_name + 1);
          temp[strlen(temp) - 1] = '\0';

          /* Get variable value */
          char *var_value = mysh_expand_variable(ctx, temp);
          mysh_free(temp);

          words[word_count++] = var_value;
        } else {
          words[word_count++] = mysh_expand_variable(ctx, var_name);
        }
      } else if (mysh_check_token(ctx, TOKEN_CMDSUBST)) {
        char *cmd_content;
        if (ctx->current_token.value[0] == '$') {
          /* $(cmd) format */
          cmd_content = mysh_strdup(ctx->current_token.value + 2);
          cmd_content[strlen(cmd_content) - 1] = '\0';
        } else {
          /* `cmd` format */
          cmd_content = mysh_strdup(ctx->current_token.value + 1);
          cmd_content[strlen(cmd_content) - 1] = '\0';
        }

        char *cmd_output = mysh_expand_command_substitution(ctx, cmd_content);
        mysh_free(cmd_content);
        words[word_count++] = cmd_output;
      }
    } else {
      mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                        "Too many items in list");
      break;
    }

    mysh_advance_token(ctx);
  }

  /* Null-terminate words array */
  words[word_count] = NULL;

  /* Check for semicolon */
  if (mysh_check_token(ctx, TOKEN_OPERATOR) &&
      ctx->current_token.op == OP_SEMICOLON) {
    mysh_advance_token(ctx);
  }

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Expect 'do' keyword */
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "do") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'do' after word list");

    for (size_t i = 0; i < word_count; i++) {
      mysh_free(words[i]);
    }
    mysh_free(words);
    mysh_free(var_name);

    return NULL;
  }

  mysh_advance_token(ctx);

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Parse loop body */
  Node *body = mysh_parse_list(ctx);
  if (!body) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected commands after 'do'");

    for (size_t i = 0; i < word_count; i++) {
      mysh_free(words[i]);
    }
    mysh_free(words);
    mysh_free(var_name);

    return NULL;
  }

  /* Skip newlines */
  while (mysh_match_token(ctx, TOKEN_NEWLINE)) {
    /* Just skip */
  }

  /* Expect 'done' keyword */
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "done") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'done' to end loop");

    for (size_t i = 0; i < word_count; i++) {
      mysh_free(words[i]);
    }
    mysh_free(words);
    mysh_free(var_name);
    mysh_free_node(body);

    return NULL;
  }

  mysh_advance_token(ctx);

  /* Create for node */
  Node *for_node = mysh_malloc(sizeof(Node));
  for_node->type = NODE_FOR;
  for_node->next = NULL;

  ForNode *for_struct = mysh_malloc(sizeof(ForNode));
  for_struct->var_name = var_name;
  for_struct->words = words;
  for_struct->word_count = word_count;
  for_struct->body = body;

  for_node->for_node = for_struct;

  return for_node;
}

static Node *mysh_parse_function(ShellContext *ctx) {
  if (!mysh_check_token(ctx, TOKEN_WORD) ||
      strcmp(ctx->current_token.value, "function") != 0) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected 'function' keyword");
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Parse function name */
  if (!mysh_check_token(ctx, TOKEN_WORD)) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected function name");
    return NULL;
  }

  char *func_name = mysh_strdup(ctx->current_token.value);
  mysh_advance_token(ctx);

  /* Expect opening brace */
  if (!mysh_check_token(ctx, TOKEN_OPERATOR) ||
      ctx->current_token.op != OP_LBRACE) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected '{' after function name");
    mysh_free(func_name);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Parse function body */
  Node *body = mysh_parse_list(ctx);
  if (!body) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected commands in function body");
    mysh_free(func_name);
    return NULL;
  }

  /* Expect closing brace */
  if (!mysh_check_token(ctx, TOKEN_OPERATOR) ||
      ctx->current_token.op != OP_RBRACE) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected '}' to end function");
    mysh_free(func_name);
    mysh_free_node(body);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Create function node */
  Node *func_node = mysh_malloc(sizeof(Node));
  func_node->type = NODE_FUNCTION;
  func_node->next = NULL;

  FunctionNode *func = mysh_malloc(sizeof(FunctionNode));
  func->name = func_name;
  func->body = body;

  func_node->function = func;

  return func_node;
}

static Node *mysh_parse_subshell(ShellContext *ctx) {
  if (!mysh_check_token(ctx, TOKEN_OPERATOR) ||
      ctx->current_token.op != OP_LPAREN) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected '(' for subshell");
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Parse subshell command */
  Node *command = mysh_parse_list(ctx);
  if (!command) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected commands in subshell");
    return NULL;
  }

  /* Expect closing parenthesis */
  if (!mysh_check_token(ctx, TOKEN_OPERATOR) ||
      ctx->current_token.op != OP_RPAREN) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected ')' to end subshell");
    mysh_free_node(command);
    return NULL;
  }

  mysh_advance_token(ctx);

  /* Create subshell node */
  Node *subshell_node = mysh_malloc(sizeof(Node));
  subshell_node->type = NODE_SUBSHELL;
  subshell_node->next = NULL;

  SubshellNode *subshell = mysh_malloc(sizeof(SubshellNode));
  subshell->command = command;

  subshell_node->subshell = subshell;

  return subshell_node;
}

static Node *mysh_parse_cmdsubst(ShellContext *ctx) {
  if (!mysh_check_token(ctx, TOKEN_CMDSUBST)) {
    mysh_report_error(ctx, ctx->current_token.line, ctx->current_token.column,
                      "Expected command substitution");
    return NULL;
  }

  /* Get the command string from the token */
  char *cmd_str = ctx->current_token.value;
  char *cmd_content = NULL;

  /* Extract actual command content from $(...) or `...` format */
  if (cmd_str[0] == '$' && cmd_str[1] == '(' &&
      cmd_str[strlen(cmd_str) - 1] == ')') {
    /* $(...) format */
    cmd_content = mysh_strdup(cmd_str + 2);
    cmd_content[strlen(cmd_content) - 1] = '\0';
  } else if (cmd_str[0] == '`' && cmd_str[strlen(cmd_str) - 1] == '`') {
    /* `...` format */
    cmd_content = mysh_strdup(cmd_str + 1);
    cmd_content[strlen(cmd_content) - 1] = '\0';
  } else {
    /* Shouldn't get here, but just in case */
    cmd_content = mysh_strdup(cmd_str);
  }

  mysh_advance_token(ctx);

  /* Create command substitution node */
  Node *cmdsubst_node = mysh_malloc(sizeof(Node));
  cmdsubst_node->type = NODE_CMDSUBST;
  cmdsubst_node->next = NULL;

  /* Parse the command content */
  ShellContext *subctx = mysh_create_context();
  mysh_init_lexer(subctx, cmd_content);
  Node *subcommand = mysh_parse(subctx);

  CmdSubstNode *cmdsubst = mysh_malloc(sizeof(CmdSubstNode));
  cmdsubst->command = subcommand;

  cmdsubst_node->cmdsubst = cmdsubst;

  /* Clean up */
  mysh_free(cmd_content);
  mysh_destroy_context(subctx);

  return cmdsubst_node;
}

static void mysh_free_node(Node *node) {
  if (!node)
    return;

  /* Free the next node in the chain */
  if (node->next) {
    mysh_free_node(node->next);
  }

  /* Free node-specific data */
  switch (node->type) {
  case NODE_COMMAND: {
    CommandNode *cmd = node->command;
    if (cmd) {
      mysh_free(cmd->name);

      for (size_t i = 0; i < cmd->arg_count; i++) {
        mysh_free(cmd->args[i]);
      }
      mysh_free(cmd->args);

      if (cmd->redirections) {
        for (size_t i = 0; i < cmd->redir_count; i++) {
          mysh_free(cmd->redirections[i].target);
        }
        mysh_free(cmd->redirections);
      }

      mysh_free(cmd);
    }
    break;
  }

  case NODE_PIPELINE: {
    PipelineNode *pipe = node->pipeline;
    if (pipe) {
      for (size_t i = 0; i < pipe->command_count; i++) {
        mysh_free_node(pipe->commands[i]);
      }
      mysh_free(pipe->commands);
      mysh_free(pipe);
    }
    break;
  }

  case NODE_LIST: {
    ListNode *list = node->list;
    if (list) {
      for (size_t i = 0; i < list->command_count; i++) {
        mysh_free_node(list->commands[i]);
      }
      mysh_free(list->commands);
      mysh_free(list->operators);
      mysh_free(list);
    }
    break;
  }

  case NODE_REDIRECTION: {
    RedirectionNode *redir = node->redirection;
    if (redir) {
      mysh_free_node(redir->command);

      if (redir->redirections) {
        for (size_t i = 0; i < redir->redir_count; i++) {
          mysh_free(redir->redirections[i].target);
        }
        mysh_free(redir->redirections);
      }

      mysh_free(redir);
    }
    break;
  }

  case NODE_ASSIGNMENT: {
    AssignmentNode *assign = node->assignment;
    if (assign) {
      mysh_free(assign->name);
      mysh_free(assign->value);
      mysh_free(assign);
    }
    break;
  }

  case NODE_IF: {
    IfNode *if_node = node->if_node;
    if (if_node) {
      mysh_free_node(if_node->condition);
      mysh_free_node(if_node->then_part);
      if (if_node->else_part) {
        mysh_free_node(if_node->else_part);
      }
      mysh_free(if_node);
    }
    break;
  }

  case NODE_WHILE: {
    WhileNode *while_node = node->while_node;
    if (while_node) {
      mysh_free_node(while_node->condition);
      mysh_free_node(while_node->body);
      mysh_free(while_node);
    }
    break;
  }

  case NODE_FOR: {
    ForNode *for_node = node->for_node;
    if (for_node) {
      mysh_free(for_node->var_name);

      for (size_t i = 0; i < for_node->word_count; i++) {
        mysh_free(for_node->words[i]);
      }
      mysh_free(for_node->words);

      mysh_free_node(for_node->body);
      mysh_free(for_node);
    }
    break;
  }

  case NODE_FUNCTION: {
    FunctionNode *func = node->function;
    if (func) {
      mysh_free(func->name);
      mysh_free_node(func->body);
      mysh_free(func);
    }
    break;
  }

  case NODE_SUBSHELL: {
    SubshellNode *subshell = node->subshell;
    if (subshell) {
      mysh_free_node(subshell->command);
      mysh_free(subshell);
    }
    break;
  }

  case NODE_CMDSUBST: {
    CmdSubstNode *cmdsubst = node->cmdsubst;
    if (cmdsubst) {
      mysh_free_node(cmdsubst->command);
      mysh_free(cmdsubst);
    }
    break;
  }
  }

  /* Free the node itself */
  mysh_free(node);
}

/*
 * Execution Functions
 */

static int mysh_execute(ShellContext *ctx, Node *node) {
  if (!ctx || !node)
    return 1;

  int result = 0;

  /* Execute all nodes in sequence */
  while (node) {
    /* Execute based on node type */
    switch (node->type) {
    case NODE_COMMAND:
      result = mysh_execute_command(ctx, node->command);
      break;

    case NODE_PIPELINE:
      result = mysh_execute_pipeline(ctx, node->pipeline);
      break;

    case NODE_LIST:
      result = mysh_execute_list(ctx, node->list);
      break;

    case NODE_REDIRECTION:
      result = mysh_execute_redirection(ctx, node->redirection);
      break;

    case NODE_ASSIGNMENT:
      result = mysh_execute_assignment(ctx, node->assignment);
      break;

    case NODE_IF:
      result = mysh_execute_if(ctx, node->if_node);
      break;

    case NODE_WHILE:
      result = mysh_execute_while(ctx, node->while_node);
      break;

    case NODE_FOR:
      result = mysh_execute_for(ctx, node->for_node);
      break;

    case NODE_FUNCTION:
      result = mysh_execute_function(ctx, node->function);
      break;

    case NODE_SUBSHELL:
      result = mysh_execute_subshell(ctx, node->subshell);
      break;

    case NODE_CMDSUBST: {
      char *output = NULL;
      result = mysh_execute_cmdsubst(ctx, node->cmdsubst, &output);
      if (output) {
        /* In direct execution, just print the output */
        printf("%s", output);
        mysh_free(output);
      }
      break;
    }

    default:
      mysh_report_error(ctx, 0, 0, "Unknown node type in execution");
      result = 1;
    }

    /* Store exit code */
    ctx->last_exit_code = result;

    /* Set $? variable */
    char exit_code_str[16];
    snprintf(exit_code_str, sizeof(exit_code_str), "%d", result);
    mysh_set_variable(ctx, "?", exit_code_str);

    /* Continue to next node in sequence */
    node = node->next;
  }

  return result;
}

static int mysh_execute_command(ShellContext *ctx, CommandNode *command) {
  if (!ctx || !command)
    return 1;

  /* Expand command substitutions in arguments */
  for (size_t i = 0; i < command->arg_count; i++) {
    if (strchr(command->args[i], '$') && strchr(command->args[i], '(')) {
      /* Find $(command) pattern */
      char *start = strstr(command->args[i], "$(");
      if (start) {
        char *end = strchr(start, ')');
        if (end) {
          /* Extract command */
          size_t cmd_len = end - start - 2;
          char *cmd = mysh_malloc(cmd_len + 1);
          strncpy(cmd, start + 2, cmd_len);
          cmd[cmd_len] = '\0';

          /* Execute command and get output */
          char *output = mysh_expand_command_substitution(ctx, cmd);
          mysh_free(cmd);

          /* Replace in original string */
          size_t prefix_len = start - command->args[i];
          size_t suffix_len = strlen(end + 1);
          size_t output_len = strlen(output);

          char *new_arg = mysh_malloc(prefix_len + output_len + suffix_len + 1);

          /* Copy prefix */
          if (prefix_len > 0) {
            strncpy(new_arg, command->args[i], prefix_len);
            new_arg[prefix_len] = '\0';
          } else {
            new_arg[0] = '\0';
          }

          /* Copy output */
          strcat(new_arg, output);

          /* Copy suffix */
          if (suffix_len > 0) {
            strcat(new_arg, end + 1);
          }

          /* Replace argument */
          mysh_free(command->args[i]);
          command->args[i] = new_arg;
          mysh_free(output);
        }
      }
    }
  }

  /* Check if it's a function */
  Function *func = mysh_get_function(ctx, command->name);
  if (func) {
    /* Save old args and set new ones */
    char *old_args[10] = {NULL};
    for (int i = 0; i < 9; i++) {
      char arg_name[3] = {'0' + i, '\0'};
      Variable *var = mysh_get_variable(ctx, arg_name);
      if (var) {
        old_args[i] = mysh_strdup(var->value);
      }

      /* Set new arg value */
      if (i < (int)(command->arg_count - 1)) {
        mysh_set_variable(ctx, arg_name, command->args[i + 1]);
      } else {
        mysh_set_variable(ctx, arg_name, "");
      }
    }

    /* Set up redirections for function execution */
    int *saved_fds = NULL;
    if (command->redir_count > 0) {
      saved_fds = mysh_malloc(sizeof(int) * command->redir_count);
      for (size_t i = 0; i < command->redir_count; i++) {
        saved_fds[i] = mysh_setup_redirection(&command->redirections[i]);
        if (saved_fds[i] == -1) {
          /* Clean up already established redirections */
          for (size_t j = 0; j < i; j++) {
            mysh_restore_redirection(&command->redirections[j], saved_fds[j]);
          }
          mysh_free(saved_fds);
          return 1;
        }
      }
    }

    /* Execute function with a new scope */
    mysh_push_scope(ctx);
    int result = mysh_execute(ctx, func->body);
    mysh_pop_scope(ctx);

    /* Restore redirections */
    if (saved_fds) {
      for (size_t i = 0; i < command->redir_count; i++) {
        mysh_restore_redirection(&command->redirections[i], saved_fds[i]);
      }
      mysh_free(saved_fds);
    }

    /* Restore old args */
    for (int i = 0; i < 9; i++) {
      if (old_args[i]) {
        char arg_name[3] = {'0' + i, '\0'};
        mysh_set_variable(ctx, arg_name, old_args[i]);
        mysh_free(old_args[i]);
      }
    }

    return result;
  }

  /* Set up redirections before executing any command */
  int *saved_fds = NULL;
  if (command->redir_count > 0) {
    saved_fds = mysh_malloc(sizeof(int) * command->redir_count);

    /* Set up all redirections */
    for (size_t i = 0; i < command->redir_count; i++) {
      saved_fds[i] = mysh_setup_redirection(&command->redirections[i]);
      if (saved_fds[i] == -1) {
        /* Clean up already established redirections */
        for (size_t j = 0; j < i; j++) {
          mysh_restore_redirection(&command->redirections[j], saved_fds[j]);
        }
        mysh_free(saved_fds);
        return 1;
      }
    }
  }

  int result;

  /* Execute the command (builtin or external) */
  if (mysh_is_builtin(command->name)) {
    result = mysh_execute_builtin(ctx, command);
  } else {
    result = mysh_execute_external(ctx, command);
  }

  /* Restore redirections */
  if (saved_fds) {
    for (size_t i = 0; i < command->redir_count; i++) {
      mysh_restore_redirection(&command->redirections[i], saved_fds[i]);
    }
    mysh_free(saved_fds);
  }

  return result;
}

static int mysh_execute_pipeline(ShellContext *ctx, PipelineNode *pipeline) {
  if (!ctx || !pipeline || pipeline->command_count == 0)
    return 1;

  /* Single command case */
  if (pipeline->command_count == 1) {
    return mysh_execute(ctx, pipeline->commands[0]);
  }

  /* Multiple commands with pipes */
  int pipe_fds[2];
  pid_t pids[pipeline->command_count];
  int status = 0;
  int prev_pipe_read = -1;

  /* Create a new process group for the pipeline if job control is active */
  pid_t pgid = 0;
  bool use_job_control = ctx->job_control_active && !pipeline->background;

  for (size_t i = 0; i < pipeline->command_count; i++) {
    /* Create pipe for all but the last command */
    if (i < pipeline->command_count - 1) {
      if (pipe(pipe_fds) == -1) {
        perror("pipe");

        /* Clean up previous processes */
        for (size_t j = 0; j < i; j++) {
          kill(pids[j], SIGTERM);
        }

        return 1;
      }
    }

    /* Fork child process */
    pid_t pid = fork();

    if (pid == -1) {
      perror("fork");

      /* Clean up resources */
      if (i < pipeline->command_count - 1) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
      }

      /* Kill previous processes */
      for (size_t j = 0; j < i; j++) {
        kill(pids[j], SIGTERM);
      }

      return 1;
    }

    if (pid == 0) {
      /* Child process */

      /* Set up process group for job control */
      if (use_job_control) {
        if (i == 0) {
          /* First process becomes group leader */
          pgid = getpid();
          setpgid(0, pgid);

          /* Give terminal control to the new process group if foreground */
          if (!pipeline->background) {
            tcsetpgrp(ctx->terminal_fd, pgid);
          }
        } else {
          /* Other processes join the same group */
          setpgid(0, pgid);
        }
      }

      /* Connect previous pipe to stdin if not the first command */
      if (prev_pipe_read != -1) {
        dup2(prev_pipe_read, STDIN_FILENO);
        close(prev_pipe_read);
      }

      /* Connect pipe output to stdout if not the last command */
      if (i < pipeline->command_count - 1) {
        dup2(pipe_fds[1], STDOUT_FILENO);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
      }

      /* Execute the command */
      _exit(mysh_execute(ctx, pipeline->commands[i]));
    }

    /* Parent process */
    pids[i] = pid;

    /* Set up process group in parent as well (to avoid race conditions) */
    if (use_job_control) {
      if (i == 0) {
        pgid = pid;
      }
      setpgid(pid, pgid);
    }

    /* Close previous pipe read end if needed */
    if (prev_pipe_read != -1) {
      close(prev_pipe_read);
    }

    /* Save the read end of the pipe for the next iteration */
    if (i < pipeline->command_count - 1) {
      prev_pipe_read = pipe_fds[0];
      close(pipe_fds[1]);
    }
  }

  /* Background the pipeline if requested */
  if (pipeline->background) {
    /* Add to job list */
    char job_cmd[MAX_LINE_LENGTH] = {0};
    strcat(job_cmd, pipeline->commands[0]->command->name);
    for (size_t i = 1; i < pipeline->command_count; i++) {
      strcat(job_cmd, " | ");
      strcat(job_cmd, pipeline->commands[i]->command->name);
    }

    int job_id = mysh_job_add(ctx, pgid, job_cmd);
    printf("[%d] %d\n", job_id, pgid);

    /* Don't wait for background jobs */
    return 0;
  } else {
    /* Wait for last command to complete */
    waitpid(pids[pipeline->command_count - 1], &status, 0);

    /* Give terminal back to shell */
    if (use_job_control) {
      tcsetpgrp(ctx->terminal_fd, ctx->shell_pgid);
    }

    /* Clean up other processes */
    for (size_t i = 0; i < pipeline->command_count - 1; i++) {
      waitpid(pids[i], NULL, 0);
    }

    return WEXITSTATUS(status);
  }
}

static int mysh_execute_list(ShellContext *ctx, ListNode *list) {
  if (!ctx || !list || list->command_count == 0)
    return 1;

  int result = 0;

  for (size_t i = 0; i < list->command_count; i++) {
    /* Execute current command */
    result = mysh_execute(ctx, list->commands[i]);
    ctx->last_exit_code = result;

    /* Handle conditional execution for && and || */
    if (i < list->command_count - 1) {
      if ((list->operators[i] == OP_AND && result != 0) ||
          (list->operators[i] == OP_OR && result == 0)) {
        /* Skip the next command based on condition */
        i++;
      }
    }
  }

  return result;
}

static int mysh_execute_redirection(ShellContext *ctx,
                                    RedirectionNode *redirection) {
  if (!ctx || !redirection)
    return 1;

  /* Save the original file descriptors */
  int *saved_fds = mysh_malloc(sizeof(int) * redirection->redir_count);

  /* Set up redirections */
  for (size_t i = 0; i < redirection->redir_count; i++) {
    saved_fds[i] = mysh_setup_redirection(&redirection->redirections[i]);
    if (saved_fds[i] == -1) {
      /* Clean up already established redirections */
      for (size_t j = 0; j < i; j++) {
        mysh_restore_redirection(&redirection->redirections[j], saved_fds[j]);
      }
      mysh_free(saved_fds);
      return 1;
    }
  }

  /* Execute the command */
  int result = mysh_execute(ctx, redirection->command);

  /* Restore redirections */
  for (size_t i = 0; i < redirection->redir_count; i++) {
    mysh_restore_redirection(&redirection->redirections[i], saved_fds[i]);
  }

  mysh_free(saved_fds);

  return result;
}

static int mysh_execute_assignment(ShellContext *ctx,
                                   AssignmentNode *assignment) {
  if (!ctx || !assignment)
    return 1;

  /* Set variable */
  Variable *var = mysh_set_variable(ctx, assignment->name, assignment->value);

  /* Export if needed */
  if (assignment->export && var) {
    mysh_export_variable(ctx, assignment->name);
  }

  return 0;
}

static int mysh_execute_if(ShellContext *ctx, IfNode *if_node) {
  if (!ctx || !if_node)
    return 1;

  /* Execute condition */
  int result = mysh_execute(ctx, if_node->condition);

  /* Choose branch based on result */
  if (result == 0) {
    /* Condition is true, execute 'then' branch */
    return mysh_execute(ctx, if_node->then_part);
  } else if (if_node->else_part) {
    /* Condition is false, execute 'else' branch if it exists */
    return mysh_execute(ctx, if_node->else_part);
  }

  return 0;
}

static int mysh_execute_while(ShellContext *ctx, WhileNode *while_node) {
  if (!ctx || !while_node)
    return 1;

  int result = 0;
  bool continue_loop = true;

  while (continue_loop) {
    /* Execute condition */
    result = mysh_execute(ctx, while_node->condition);

    /* Decide whether to execute body */
    if ((!while_node->until && result == 0) ||
        (while_node->until && result != 0)) {
      /* Condition is satisfied, execute body */
      result = mysh_execute(ctx, while_node->body);

      /* Check for break or continue */
      Variable *break_var = mysh_get_variable(ctx, "BREAK");
      if (break_var && strcmp(break_var->value, "1") == 0) {
        mysh_set_variable(ctx, "BREAK", "0");
        break;
      }

      Variable *continue_var = mysh_get_variable(ctx, "CONTINUE");
      if (continue_var && strcmp(continue_var->value, "1") == 0) {
        mysh_set_variable(ctx, "CONTINUE", "0");
        continue;
      }
    } else {
      /* Condition is not satisfied, exit loop */
      break;
    }
  }

  return result;
}

static int mysh_execute_for(ShellContext *ctx, ForNode *for_node) {
  if (!ctx || !for_node)
    return 1;

  int result = 0;

  /* Create a new scope for the loop */
  mysh_push_scope(ctx);

  /* Loop through each word */
  for (size_t i = 0; i < for_node->word_count; i++) {
    /* Set loop variable */
    mysh_set_variable(ctx, for_node->var_name, for_node->words[i]);

    /* Execute body */
    result = mysh_execute(ctx, for_node->body);

    /* Check for break */
    Variable *break_var = mysh_get_variable(ctx, "BREAK");
    if (break_var && strcmp(break_var->value, "1") == 0) {
      mysh_set_variable(ctx, "BREAK", "0");
      break;
    }

    /* Check for continue */
    Variable *continue_var = mysh_get_variable(ctx, "CONTINUE");
    if (continue_var && strcmp(continue_var->value, "1") == 0) {
      mysh_set_variable(ctx, "CONTINUE", "0");
      continue;
    }
  }

  /* Restore previous scope */
  mysh_pop_scope(ctx);

  return result;
}

static int mysh_execute_function(ShellContext *ctx, FunctionNode *function) {
  if (!ctx || !function)
    return 1;

  /* Define the function */
  mysh_set_function(ctx, function->name, function->body);

  return 0;
}

static int mysh_execute_subshell(ShellContext *ctx, SubshellNode *subshell) {
  if (!ctx || !subshell)
    return 1;

  /* Fork a subshell */
  pid_t pid = fork();

  if (pid == -1) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    /* Child process */

    /* Create a new scope */
    mysh_push_scope(ctx);

    /* Execute the command */
    int result = mysh_execute(ctx, subshell->command);

    /* Exit with the result */
    _exit(result);
  }

  /* Parent process */
  int status;
  waitpid(pid, &status, 0);

  return WEXITSTATUS(status);
}

static int mysh_execute_cmdsubst(ShellContext *ctx, CmdSubstNode *cmdsubst,
                                 char **output) {
  if (!ctx || !cmdsubst) {
    if (output)
      *output = mysh_strdup("");
    return 1;
  }

  /* Create pipes for capturing output */
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    perror("pipe");
    if (output)
      *output = mysh_strdup("");
    return 1;
  }

  /* Fork process */
  pid_t pid = fork();

  if (pid == -1) {
    perror("fork");
    close(pipefd[0]);
    close(pipefd[1]);
    if (output)
      *output = mysh_strdup("");
    return 1;
  }

  if (pid == 0) {
    /* Child process */

    /* Redirect stdout to the pipe */
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);

    /* Create a new scope */
    mysh_push_scope(ctx);

    /* Execute the command */
    int result = mysh_execute(ctx, cmdsubst->command);

    /* Exit with the result */
    _exit(result);
  }

  /* Parent process */
  close(pipefd[1]); /* Close write end */

  /* Read output from the pipe */
  char buffer[4096];
  ssize_t bytes_read;
  char *result = NULL;

  if (output) {
    result = mysh_malloc(1);
    result[0] = '\0';
  }

  while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
    if (output) {
      buffer[bytes_read] = '\0';

      /* Remove trailing newlines */
      if (bytes_read > 0 && buffer[bytes_read - 1] == '\n') {
        buffer[bytes_read - 1] = '\0';
        bytes_read--;
      }

      /* Append to result */
      size_t cur_len = strlen(result);
      result = mysh_realloc(result, cur_len + bytes_read + 1);
      strcat(result, buffer);
    }
  }

  close(pipefd[0]); /* Close read end */

  /* Wait for child to complete */
  int status;
  waitpid(pid, &status, 0);

  if (output) {
    *output = result;
  }

  return WEXITSTATUS(status);
}

static char *mysh_expand_command_substitution(ShellContext *ctx,
                                              const char *cmdsubst) {
  if (!ctx || !cmdsubst)
    return mysh_strdup("");

  /* Create pipes for capturing output */
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    perror("pipe");
    return mysh_strdup("");
  }

  /* Fork process */
  pid_t pid = fork();

  if (pid == -1) {
    perror("fork");
    close(pipefd[0]);
    close(pipefd[1]);
    return mysh_strdup("");
  }

  if (pid == 0) {
    /* Child process */

    /* Redirect stdout to the pipe */
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[0]);
    close(pipefd[1]);

    /* Create a new shell context */
    ShellContext *child_ctx = mysh_create_context();

    /* Copy environment from parent */
    EnvScope *scope = ctx->current_scope;
    while (scope) {
      pthread_mutex_lock(&scope->mutex);
      for (size_t i = 0; i < scope->var_count; i++) {
        if (scope->variables[i]->exported) {
          mysh_set_variable(child_ctx, scope->variables[i]->name,
                            scope->variables[i]->value);
          mysh_export_variable(child_ctx, scope->variables[i]->name);
        }
      }
      pthread_mutex_unlock(&scope->mutex);
      scope = scope->parent;
    }

    /* Execute the command */
    mysh_run_string(child_ctx, cmdsubst);

    /* Clean up */
    mysh_destroy_context(child_ctx);

    /* Exit */
    _exit(0);
  }

  /* Parent process */
  close(pipefd[1]); /* Close write end */

  /* Read output from the pipe */
  char buffer[4096];
  ssize_t bytes_read;
  char *result = mysh_malloc(1);
  result[0] = '\0';
  size_t total_size = 1;

  while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
    buffer[bytes_read] = '\0';

    /* Resize result buffer */
    total_size += bytes_read;
    result = mysh_realloc(result, total_size);

    /* Append to result */
    strcat(result, buffer);
  }

  /* Remove trailing newlines */
  size_t len = strlen(result);
  while (len > 0 && result[len - 1] == '\n') {
    result[--len] = '\0';
  }

  close(pipefd[0]); /* Close read end */

  /* Wait for child to complete */
  waitpid(pid, NULL, 0);

  return result;
}

static int mysh_execute_builtin(ShellContext *ctx, CommandNode *command) {
  if (!ctx || !command)
    return 1;

  /* Convert command args format */
  int argc = command->arg_count;
  char **argv = command->args;

  /* Match and execute builtin */
  if (strcmp(command->name, "cd") == 0) {
    return mysh_builtin_cd(ctx, argc, argv);
  } else if (strcmp(command->name, "pwd") == 0) {
    return mysh_builtin_pwd(ctx, argc, argv);
  } else if (strcmp(command->name, "exit") == 0) {
    return mysh_builtin_exit(ctx, argc, argv);
  } else if (strcmp(command->name, "export") == 0) {
    return mysh_builtin_export(ctx, argc, argv);
  } else if (strcmp(command->name, "unset") == 0) {
    return mysh_builtin_unset(ctx, argc, argv);
  } else if (strcmp(command->name, "echo") == 0) {
    return mysh_builtin_echo(ctx, argc, argv);
  } else if (strcmp(command->name, "set") == 0) {
    return mysh_builtin_set(ctx, argc, argv);
  } else if (strcmp(command->name, "alias") == 0) {
    return mysh_builtin_alias(ctx, argc, argv);
  } else if (strcmp(command->name, "unalias") == 0) {
    return mysh_builtin_unalias(ctx, argc, argv);
  } else if (strcmp(command->name, "source") == 0 ||
             strcmp(command->name, ".") == 0) {
    return mysh_builtin_source(ctx, argc, argv);
  } else if (strcmp(command->name, "jobs") == 0) {
    return mysh_builtin_jobs(ctx, argc, argv);
  } else if (strcmp(command->name, "fg") == 0) {
    return mysh_builtin_fg(ctx, argc, argv);
  } else if (strcmp(command->name, "bg") == 0) {
    return mysh_builtin_bg(ctx, argc, argv);
  }

  return MYSH_ERROR_COMMAND_NOT_FOUND;
}

static int mysh_execute_external(ShellContext *ctx, CommandNode *command) {
  if (!ctx || !command)
    return 1;

  /* Resolve command path */
  char cmd_path[MAX_PATH_LENGTH];
  if (mysh_find_command_path(command->name, cmd_path, MAX_PATH_LENGTH) != 0) {
    mysh_report_error(ctx, 0, 0, "Command not found");
    return MYSH_ERROR_COMMAND_NOT_FOUND;
  }

  /* Fork process */
  pid_t pid = fork();

  if (pid == -1) {
    perror("fork");
    return 1;
  }

  if (pid == 0) {
    /* Child process */

    /* Set up job control */
    if (ctx->job_control_active) {
      /* Create new process group */
      pid_t pgid = getpid();
      setpgid(0, pgid);

      /* Give terminal control if foreground */
      if (!command->background) {
        tcsetpgrp(ctx->terminal_fd, pgid);
      }

      /* Reset signal handlers */
      signal(SIGINT, SIG_DFL);
      signal(SIGQUIT, SIG_DFL);
      signal(SIGTSTP, SIG_DFL);
      signal(SIGTTIN, SIG_DFL);
      signal(SIGTTOU, SIG_DFL);
      signal(SIGCHLD, SIG_DFL);
    }

    /* Set up redirections if any */
    for (size_t i = 0; i < command->redir_count; i++) {
      if (mysh_setup_redirection(&command->redirections[i]) == -1) {
        _exit(1);
      }
    }

    /* Execute command */
    execvp(cmd_path, command->args);

    /* If we get here, exec failed */
    perror("execvp");
    _exit(127);
  }

  /* Parent process */

  /* Set up job control in parent as well */
  if (ctx->job_control_active) {
    setpgid(pid, pid); /* Use pid as pgid */
  }

  if (command->background) {
    /* Background command */
    int job_id = mysh_job_add(ctx, pid, command->name);
    printf("[%d] %d\n", job_id, pid);
    return 0;
  } else {
    /* Wait for foreground command */
    int status;

    /* Give terminal to the process */
    if (ctx->job_control_active) {
      tcsetpgrp(ctx->terminal_fd, pid);
    }

    /* Wait for it to complete */
    waitpid(pid, &status, WUNTRACED);

    /* Take terminal back */
    if (ctx->job_control_active) {
      tcsetpgrp(ctx->terminal_fd, ctx->shell_pgid);
    }

    /* Check if process was stopped */
    if (WIFSTOPPED(status)) {
      int job_id = mysh_job_add(ctx, pid, command->name);
      mysh_job_mark_status(ctx, pid, JOB_STOPPED);
      printf("\n[%d]+ Stopped\t%s\n", job_id, command->name);
      return 128 + WSTOPSIG(status);
    }

    /* Return the exit status */
    if (WIFEXITED(status)) {
      return WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
      return 128 + WTERMSIG(status);
    }

    return 1;
  }
}

/*
 * Job Control Functions
 */

static int mysh_init_job_control(ShellContext *ctx) {
  if (!ctx)
    return -1;

  /* Initialize job slots */
  memset(ctx->jobs, 0, sizeof(ctx->jobs));
  for (size_t i = 0; i < MAX_JOBS; i++) {
    atomic_init(&ctx->jobs[i].in_use, false);
  }
  ctx->job_count = 0;

  /* Save shell process group ID */
  ctx->shell_pgid = getpid();

  /* Get terminal file descriptor */
  ctx->terminal_fd = STDIN_FILENO;

  /* Save terminal settings */
  tcgetattr(ctx->terminal_fd, &ctx->original_termios);

  /* Put shell in its own process group */
  setpgid(0, ctx->shell_pgid);

  /* Take control of the terminal */
  tcsetpgrp(ctx->terminal_fd, ctx->shell_pgid);

  /* Enable job control */
  ctx->job_control_active = true;

  /* Set up signal handlers */
  signal(SIGINT, SIG_IGN);
  signal(SIGQUIT, SIG_IGN);
  signal(SIGTSTP, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);

  /* Install SIGCHLD handler that sets a flag or updates job status */
  signal(SIGCHLD, SIG_DFL);

  return 0;
}

static void mysh_cleanup_job_control(ShellContext *ctx) {
  if (!ctx)
    return;

  /* Restore terminal settings */
  if (ctx->job_control_active) {
    tcsetattr(ctx->terminal_fd, TCSADRAIN, &ctx->original_termios);
  }

  /* Kill any remaining jobs */
  for (size_t i = 0; i < MAX_JOBS; i++) {
    if (atomic_load(&ctx->jobs[i].in_use)) {
      kill(-ctx->jobs[i].pid, SIGTERM);
    }
  }
}

static int mysh_job_add(ShellContext *ctx, pid_t pid, const char *command) {
  if (!ctx)
    return -1;

  pthread_mutex_lock(&ctx->mutex);

  /* Find a free slot */
  int job_id = -1;
  for (size_t i = 0; i < MAX_JOBS; i++) {
    if (!atomic_load(&ctx->jobs[i].in_use)) {
      job_id = i + 1; /* Job IDs start at 1 */
      atomic_store(&ctx->jobs[i].in_use, true);
      ctx->jobs[i].pid = pid;
      ctx->jobs[i].command = mysh_strdup(command);
      ctx->jobs[i].status = JOB_RUNNING;

      /* Save terminal modes for job control */
      tcgetattr(ctx->terminal_fd, &ctx->jobs[i].tmodes);

      ctx->job_count++;
      break;
    }
  }

  pthread_mutex_unlock(&ctx->mutex);

  return job_id;
}

static int mysh_job_remove(ShellContext *ctx, pid_t pid) {
  if (!ctx)
    return -1;

  pthread_mutex_lock(&ctx->mutex);

  /* Find the job */
  for (size_t i = 0; i < MAX_JOBS; i++) {
    if (atomic_load(&ctx->jobs[i].in_use) && ctx->jobs[i].pid == pid) {
      /* Free job slot */
      mysh_free(ctx->jobs[i].command);
      atomic_store(&ctx->jobs[i].in_use, false);
      ctx->job_count--;

      pthread_mutex_unlock(&ctx->mutex);
      return 0;
    }
  }

  pthread_mutex_unlock(&ctx->mutex);
  return -1;
}

static int mysh_job_mark_status(ShellContext *ctx, pid_t pid,
                                JobStatus status) {
  if (!ctx)
    return -1;

  pthread_mutex_lock(&ctx->mutex);

  /* Find the job */
  for (size_t i = 0; i < MAX_JOBS; i++) {
    if (atomic_load(&ctx->jobs[i].in_use) && ctx->jobs[i].pid == pid) {
      /* Update status */
      ctx->jobs[i].status = status;

      pthread_mutex_unlock(&ctx->mutex);
      return 0;
    }
  }

  pthread_mutex_unlock(&ctx->mutex);
  return -1;
}

static void mysh_job_update_status(ShellContext *ctx) {
  if (!ctx)
    return;

  pid_t pid;
  int status;

  /* Check for any completed jobs */
  while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED | WCONTINUED)) > 0) {
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      /* Job completed */
      for (size_t i = 0; i < MAX_JOBS; i++) {
        if (atomic_load(&ctx->jobs[i].in_use) && ctx->jobs[i].pid == pid) {
          printf("[%zu] Done\t%s\n", i + 1, ctx->jobs[i].command);

          /* Remove job */
          mysh_job_remove(ctx, pid);
          break;
        }
      }
    } else if (WIFSTOPPED(status)) {
      /* Job stopped */
      mysh_job_mark_status(ctx, pid, JOB_STOPPED);
    } else if (WIFCONTINUED(status)) {
      /* Job continued */
      mysh_job_mark_status(ctx, pid, JOB_RUNNING);
    }
  }
}

static int mysh_job_foreground(ShellContext *ctx, int job_id, bool cont) {
  if (!ctx || job_id <= 0 || job_id > MAX_JOBS)
    return -1;

  int i = job_id - 1; /* Convert to 0-based index */

  /* Verify job exists */
  if (!atomic_load(&ctx->jobs[i].in_use)) {
    mysh_report_error(ctx, 0, 0, "No such job");
    return -1;
  }

  pid_t pid = ctx->jobs[i].pid;

  /* Put job in foreground */
  tcsetpgrp(ctx->terminal_fd, pid);

  /* Restore terminal modes */
  tcsetattr(ctx->terminal_fd, TCSADRAIN, &ctx->jobs[i].tmodes);

  /* Continue job if requested */
  if (cont && ctx->jobs[i].status == JOB_STOPPED) {
    kill(-pid, SIGCONT);
    ctx->jobs[i].status = JOB_RUNNING;
  }

  /* Wait for job to complete or stop */
  int status;
  waitpid(pid, &status, WUNTRACED);

  /* Put shell back in foreground */
  tcsetpgrp(ctx->terminal_fd, ctx->shell_pgid);

  /* Save terminal modes */
  tcgetattr(ctx->terminal_fd, &ctx->jobs[i].tmodes);

  /* Restore shell's terminal modes */
  tcsetattr(ctx->terminal_fd, TCSADRAIN, &ctx->original_termios);

  /* Update job status */
  if (WIFEXITED(status)) {
    /* Job completed */
    mysh_job_remove(ctx, pid);
    return WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    /* Job terminated by signal */
    mysh_job_remove(ctx, pid);
    return 128 + WTERMSIG(status);
  } else if (WIFSTOPPED(status)) {
    /* Job stopped */
    ctx->jobs[i].status = JOB_STOPPED;
    printf("\n[%d]+ Stopped\t%s\n", job_id, ctx->jobs[i].command);
    return 128 + WSTOPSIG(status);
  }

  return 0;
}

static int mysh_job_background(ShellContext *ctx, int job_id, bool cont) {
  if (!ctx || job_id <= 0 || job_id > MAX_JOBS)
    return -1;

  int i = job_id - 1; /* Convert to 0-based index */

  /* Verify job exists */
  if (!atomic_load(&ctx->jobs[i].in_use)) {
    mysh_report_error(ctx, 0, 0, "No such job");
    return -1;
  }

  pid_t pid = ctx->jobs[i].pid;

  /* Continue job if requested */
  if (cont && ctx->jobs[i].status == JOB_STOPPED) {
    kill(-pid, SIGCONT);
    ctx->jobs[i].status = JOB_RUNNING;
    printf("[%d]+ %s &\n", job_id, ctx->jobs[i].command);
  }

  return 0;
}

static void mysh_job_print(ShellContext *ctx, int job_id) {
  if (!ctx || job_id <= 0 || job_id > MAX_JOBS)
    return;

  size_t i = job_id - 1; /* Convert to 0-based index */

  /* Verify job exists */
  if (!atomic_load(&ctx->jobs[i].in_use)) {
    return;
  }

  /* Print job information */
  const char *status_str = "Unknown";
  switch (ctx->jobs[i].status) {
  case JOB_RUNNING:
    status_str = "Running";
    break;
  case JOB_STOPPED:
    status_str = "Stopped";
    break;
  case JOB_DONE:
    status_str = "Done";
    break;
  }

  printf("[%d]%c %s\t%s\n", job_id, (i == ctx->job_count - 1) ? '+' : ' ',
         status_str, ctx->jobs[i].command);
}

static void mysh_job_print_all(ShellContext *ctx) {
  if (!ctx)
    return;

  for (size_t i = 0; i < MAX_JOBS; i++) {
    if (atomic_load(&ctx->jobs[i].in_use)) {
      mysh_job_print(ctx, i + 1);
    }
  }
}

/*
 * Builtin Command Implementations
 */

static int mysh_builtin_cd(ShellContext *ctx, int argc, char **argv) {
  const char *target_dir;

  /* Use HOME if no argument provided */
  if (argc < 2) {
    target_dir = getenv("HOME");
    if (!target_dir) {
      fprintf(stderr, "cd: HOME not set\n");
      return 1;
    }
  } else {
    target_dir = argv[1];
  }

  /* Handle tilde expansion */
  char *expanded_path = mysh_expand_tilde(target_dir);

  /* Change directory */
  if (chdir(expanded_path) != 0) {
    perror("cd");
    mysh_free(expanded_path);
    return 1;
  }

  /* Update PWD environment variable */
  if (getcwd(ctx->cwd, MAX_PATH_LENGTH) == NULL) {
    perror("getcwd");
    mysh_free(expanded_path);
    return 1;
  }

  /* Update PWD variable */
  mysh_set_variable(ctx, "PWD", ctx->cwd);
  setenv("PWD", ctx->cwd, 1);

  mysh_free(expanded_path);
  return 0;
}

static int mysh_builtin_pwd(ShellContext *ctx, int argc, char **argv) {
  /* Mark parameters as unused */
  (void)ctx;
  (void)argc;
  (void)argv;

  char cwd[MAX_PATH_LENGTH];

  if (getcwd(cwd, MAX_PATH_LENGTH) == NULL) {
    perror("pwd");
    return 1;
  }

  printf("%s\n", cwd);
  return 0;
}

static int mysh_builtin_exit(ShellContext *ctx, int argc, char **argv) {
  int status = 0;

  /* Parse exit status if provided */
  if (argc > 1) {
    status = atoi(argv[1]);
  }

  /* Set running flag to false */
  atomic_store(&ctx->is_running, false);

  /* Return exit status */
  return status;
}

static int mysh_builtin_export(ShellContext *ctx, int argc, char **argv) {
  /* Check if any arguments are provided */
  if (argc < 2) {
    /* No arguments, show all exported variables */
    pthread_mutex_lock(&ctx->global_scope->mutex);

    for (size_t i = 0; i < ctx->global_scope->var_count; i++) {
      if (ctx->global_scope->variables[i]->exported) {
        printf("export %s=\"%s\"\n", ctx->global_scope->variables[i]->name,
               ctx->global_scope->variables[i]->value);
      }
    }

    pthread_mutex_unlock(&ctx->global_scope->mutex);
    return 0;
  }

  /* Process each argument */
  for (int i = 1; i < argc; i++) {
    char *arg = argv[i];
    char *equals = strchr(arg, '=');

    if (equals) {
      /* Handle NAME=VALUE format */
      *equals = '\0'; /* Split string at equals sign */

      /* Set variable and mark as exported */
      mysh_set_variable(ctx, arg, equals + 1);
      mysh_export_variable(ctx, arg);

      /* Restore original string */
      *equals = '=';
    } else {
      /* Just mark existing variable as exported */
      mysh_export_variable(ctx, arg);
    }
  }

  return 0;
}

static int mysh_builtin_unset(ShellContext *ctx, int argc, char **argv) {
  /* Process each argument */
  for (int i = 1; i < argc; i++) {
    /* Find variable in current scope */
    pthread_mutex_lock(&ctx->current_scope->mutex);

    for (size_t j = 0; j < ctx->current_scope->var_count; j++) {
      if (strcmp(ctx->current_scope->variables[j]->name, argv[i]) == 0) {
        /* Skip if readonly */
        if (ctx->current_scope->variables[j]->readonly) {
          fprintf(stderr, "unset: %s: readonly variable\n", argv[i]);
          continue;
        }

        /* Remove variable */
        mysh_free(ctx->current_scope->variables[j]->name);
        mysh_free(ctx->current_scope->variables[j]->value);
        mysh_free(ctx->current_scope->variables[j]);

        /* Shift remaining variables */
        if (j < ctx->current_scope->var_count - 1) {
          memmove(&ctx->current_scope->variables[j],
                  &ctx->current_scope->variables[j + 1],
                  (ctx->current_scope->var_count - j - 1) * sizeof(Variable *));
        }

        ctx->current_scope->var_count--;
        break;
      }
    }

    pthread_mutex_unlock(&ctx->current_scope->mutex);

    /* Remove from environment as well */
    unsetenv(argv[i]);
  }

  return 0;
}

static int mysh_builtin_echo(ShellContext *ctx, int argc, char **argv) {
  /* Mark ctx as unused */
  (void)ctx;

  bool no_newline = false;
  int start_idx = 1;

  /* Check for options */
  if (argc > 1 && strcmp(argv[1], "-n") == 0) {
    no_newline = true;
    start_idx = 2;
  }

  /* Print arguments */
  for (int i = start_idx; i < argc; i++) {
    printf("%s", argv[i]);
    if (i < argc - 1) {
      printf(" ");
    }
  }

  if (!no_newline) {
    printf("\n");
  }

  return 0;
}

static int mysh_builtin_set(ShellContext *ctx, int argc, char **argv) {
  /* Mark argv as used */
  (void)argv;

  /* No arguments, show all variables */
  if (argc == 1) {
    /* Show all variables in current scope */
    EnvScope *scope = ctx->current_scope;
    while (scope) {
      pthread_mutex_lock(&scope->mutex);

      for (size_t i = 0; i < scope->var_count; i++) {
        printf("%s=%s\n", scope->variables[i]->name,
               scope->variables[i]->value);
      }

      pthread_mutex_unlock(&scope->mutex);
      scope = scope->parent;
    }

    return 0;
  }

  /* Process options */
  for (int i = 1; i < argc; i++) {
    /* TODO: Implement set options like -e, -x, etc. */
  }

  return 0;
}

static int mysh_builtin_alias(ShellContext *ctx, int argc, char **argv) {
  /* No arguments, show all aliases */
  if (argc == 1) {
    for (size_t i = 0; i < ctx->alias_count; i++) {
      printf("alias %s='%s'\n", ctx->aliases[i]->name, ctx->aliases[i]->value);
    }

    return 0;
  }

  /* Process each argument */
  for (int i = 1; i < argc; i++) {
    char *arg = argv[i];
    char *equals = strchr(arg, '=');

    if (equals) {
      /* Handle NAME=VALUE format */
      *equals = '\0'; /* Split string at equals sign */

      /* Set alias */
      mysh_set_alias(ctx, arg, equals + 1);

      /* Restore original string */
      *equals = '=';
    } else {
      /* Show specific alias */
      Alias *alias = mysh_get_alias(ctx, arg);
      if (alias) {
        printf("alias %s='%s'\n", alias->name, alias->value);
      }
    }
  }

  return 0;
}

static int mysh_builtin_unalias(ShellContext *ctx, int argc, char **argv) {
  /* Process each argument */
  for (int i = 1; i < argc; i++) {
    pthread_mutex_lock(&ctx->mutex);

    for (size_t j = 0; j < ctx->alias_count; j++) {
      if (strcmp(ctx->aliases[j]->name, argv[i]) == 0) {
        /* Remove alias */
        mysh_free(ctx->aliases[j]->name);
        mysh_free(ctx->aliases[j]->value);
        mysh_free(ctx->aliases[j]);

        /* Shift remaining aliases */
        if (j < ctx->alias_count - 1) {
          memmove(&ctx->aliases[j], &ctx->aliases[j + 1],
                  (ctx->alias_count - j - 1) * sizeof(Alias *));
        }

        ctx->alias_count--;
        break;
      }
    }

    pthread_mutex_unlock(&ctx->mutex);
  }

  return 0;
}

static int mysh_builtin_source(ShellContext *ctx, int argc, char **argv) {
  if (argc < 2) {
    fprintf(stderr, "source: filename argument required\n");
    return 1;
  }

  /* Expand tilde if needed */
  char *expanded_path = mysh_expand_tilde(argv[1]);

  /* Read file */
  FILE *file = fopen(expanded_path, "r");
  if (!file) {
    perror("source");
    mysh_free(expanded_path);
    return 1;
  }

  /* Read file contents */
  char *buffer = NULL;
  size_t file_size = 0;

  /* Get file size */
  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  /* Allocate buffer */
  buffer = mysh_malloc(file_size + 1);
  if (!buffer) {
    fclose(file);
    mysh_free(expanded_path);
    return 1;
  }

  /* Read file */
  if (fread(buffer, 1, file_size, file) != file_size) {
    perror("source");
    fclose(file);
    mysh_free(buffer);
    mysh_free(expanded_path);
    return 1;
  }

  buffer[file_size] = '\0';
  fclose(file);

  /* Execute file contents */
  int result = mysh_run_string(ctx, buffer);

  /* Clean up */
  mysh_free(buffer);
  mysh_free(expanded_path);

  return result;
}

static int mysh_builtin_jobs(ShellContext *ctx, int argc, char **argv) {
  /* Mark parameters as unused */
  (void)argc;
  (void)argv;

  /* Update job status */
  mysh_job_update_status(ctx);

  /* Print all jobs */
  mysh_job_print_all(ctx);

  return 0;
}

static int mysh_builtin_fg(ShellContext *ctx, int argc, char **argv) {
  int job_id = 0;

  /* Find job ID to foreground */
  if (argc > 1) {
    /* Parse job ID from argument */
    if (argv[1][0] == '%') {
      job_id = atoi(argv[1] + 1);
    } else {
      job_id = atoi(argv[1]);
    }
  } else {
    /* Find the most recent job */
    for (int i = MAX_JOBS - 1; i >= 0; i--) {
      if (atomic_load(&ctx->jobs[i].in_use)) {
        job_id = i + 1;
        break;
      }
    }
  }

  if (job_id <= 0) {
    fprintf(stderr, "fg: no current job\n");
    return 1;
  }

  /* Bring job to foreground */
  return mysh_job_foreground(ctx, job_id, true);
}

static int mysh_builtin_bg(ShellContext *ctx, int argc, char **argv) {
  int job_id = 0;

  /* Find job ID to background */
  if (argc > 1) {
    /* Parse job ID from argument */
    if (argv[1][0] == '%') {
      job_id = atoi(argv[1] + 1);
    } else {
      job_id = atoi(argv[1]);
    }
  } else {
    /* Find the most recent stopped job */
    for (int i = MAX_JOBS - 1; i >= 0; i--) {
      if (atomic_load(&ctx->jobs[i].in_use) &&
          ctx->jobs[i].status == JOB_STOPPED) {
        job_id = i + 1;
        break;
      }
    }
  }

  if (job_id <= 0) {
    fprintf(stderr, "bg: no current job\n");
    return 1;
  }

  /* Continue job in background */
  return mysh_job_background(ctx, job_id, true);
}

/*
 * Utility Functions
 */

static void mysh_report_error(ShellContext *ctx, size_t line, size_t column,
                              const char *message) {
  if (!ctx || !message)
    return;

  if (ctx->error_callback) {
    /* Use custom error callback for embedding */
    ctx->error_callback(ctx->input, line, column, message);
  } else if (ctx->interactive) {
    /* Interactive mode */
    fprintf(stderr, "myshell: %s\n", message);
  } else {
    /* Script mode */
    if (line > 0) {
      fprintf(stderr, "myshell: line %zu, column %zu: %s\n", line, column,
              message);
    } else {
      fprintf(stderr, "myshell: %s\n", message);
    }
  }
}

static char *mysh_expand_tilde(const char *path) {
  if (!path)
    return NULL;

  /* Check if path starts with ~ */
  if (path[0] == '~') {
    const char *home;

    if (path[1] == '/' || path[1] == '\0') {
      /* ~/path or ~ */
      home = getenv("HOME");
      if (!home) {
        home = "/";
      }

      /* Allocate space for expanded path */
      size_t home_len = strlen(home);
      size_t path_len = strlen(path + 1);
      char *expanded = mysh_malloc(home_len + path_len + 1);

      /* Combine paths */
      strcpy(expanded, home);
      strcat(expanded, path + 1);

      return expanded;
    } else {
      /* ~user/path - not supported yet */
      return mysh_strdup(path);
    }
  } else {
    /* No tilde, just return a copy */
    return mysh_strdup(path);
  }
}

static int mysh_setup_redirection(Redirection *redir) {
  if (!redir)
    return -1;

  int fd = -1;
  int saved_fd = -1;

  /* Convert target to an integer if it's for file descriptor duplication */
  int target_fd = -1;
  if (redir->type == REDIR_DUPFD) {
    target_fd = atoi(redir->target);
  }

  /* Save original file descriptor */
  saved_fd = dup(redir->fd);
  if (saved_fd == -1) {
    perror("dup");
    return -1;
  }

  /* Set up redirect based on type */
  switch (redir->type) {
  case REDIR_IN:
    fd = open(redir->target, O_RDONLY);
    if (fd == -1) {
      perror(redir->target);
      close(saved_fd);
      return -1;
    }
    break;

  case REDIR_OUT:
    fd = open(redir->target, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd == -1) {
      perror(redir->target);
      close(saved_fd);
      return -1;
    }
    break;

  case REDIR_APPEND:
    fd = open(redir->target, O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (fd == -1) {
      perror(redir->target);
      close(saved_fd);
      return -1;
    }
    break;

  case REDIR_HEREDOC:
    /* NOT IMPLEMENTED - would need complex parsing */
    fprintf(stderr, "Heredoc not implemented yet\n");
    close(saved_fd);
    return -1;

  case REDIR_DUPFD:
    /* Just duplicate target_fd to redir->fd */
    if (dup2(target_fd, redir->fd) == -1) {
      perror("dup2");
      close(saved_fd);
      return -1;
    }
    return saved_fd;

  default:
    fprintf(stderr, "Unknown redirection type\n");
    close(saved_fd);
    return -1;
  }

  /* Redirect file descriptor */
  if (dup2(fd, redir->fd) == -1) {
    perror("dup2");
    close(fd);
    close(saved_fd);
    return -1;
  }

  /* Close the original fd, we've duplicated it */
  close(fd);

  return saved_fd;
}

static void mysh_restore_redirection(Redirection *redir, int saved_fd) {
  if (!redir || saved_fd == -1)
    return;

  /* Restore original file descriptor */
  if (dup2(saved_fd, redir->fd) == -1) {
    perror("dup2 (restore)");
  }

  /* Close saved fd */
  close(saved_fd);
}

static bool mysh_is_builtin(const char *command) {
  if (!command)
    return false;

  static const char *builtins[] = {"cd",   "pwd",  "exit",  "export",  "unset",
                                   "echo", "set",  "alias", "unalias", "source",
                                   ".",    "jobs", "fg",    "bg",      NULL};

  for (int i = 0; builtins[i]; i++) {
    if (strcmp(command, builtins[i]) == 0) {
      return true;
    }
  }

  return false;
}

static int mysh_find_command_path(const char *command, char *result,
                                  size_t size) {
  if (!command || !result || size == 0)
    return -1;

  /* If command contains a slash, it's an absolute or relative path */
  if (strchr(command, '/')) {
    if (access(command, X_OK) == 0) {
      strncpy(result, command, size - 1);
      result[size - 1] = '\0';
      return 0;
    }
    return -1;
  }

  /* Check in PATH */
  const char *path_env = getenv("PATH");
  if (!path_env)
    path_env = "/bin:/usr/bin";

  char *path = mysh_strdup(path_env);
  char *dir = strtok(path, ":");

  while (dir) {
    /* Construct full path */
    snprintf(result, size, "%s/%s", dir, command);

    /* Check if executable */
    if (access(result, X_OK) == 0) {
      mysh_free(path);
      return 0;
    }

    dir = strtok(NULL, ":");
  }

  mysh_free(path);
  return -1;
}

static bool mysh_is_shebang_line(const char *line) {
  return line && line[0] == '#' && line[1] == '!';
}

static void mysh_handle_shebang(ShellContext *ctx) {
  if (!ctx || ctx->input_pos > 0)
    return;

  /* Check if the first line is a shebang */
  if (mysh_is_shebang_line(ctx->input)) {
    /* Skip to the end of the line */
    while (ctx->input_pos < ctx->input_length &&
           ctx->input[ctx->input_pos] != '\n') {
      mysh_advance_char(ctx);
    }

    /* Skip the newline itself */
    if (ctx->input_pos < ctx->input_length &&
        ctx->input[ctx->input_pos] == '\n') {
      mysh_advance_char(ctx);
    }
  }
}

/*
 * Interactive Shell Functions
 */

static void mysh_interactive_loop(ShellContext *ctx) {
  if (!ctx)
    return;

  /* Mark shell as interactive */
  ctx->interactive = true;

  /* Initialize termline for interactive editing */
  mysh_initialize_termline(ctx);

  /* Initialize job control */
  mysh_init_job_control(ctx);

  /* Mark as running */
  atomic_store(&ctx->is_running, true);

  char *input;
  int exit_code = 0;

  /* Main loop */
  while (atomic_load(&ctx->is_running)) {
    /* Update job status */
    mysh_job_update_status(ctx);

    /* Build prompt */
    char prompt[MAX_PATH_LENGTH + 16];
    snprintf(prompt, sizeof(prompt), "%s $ ", ctx->cwd);

    /* Read line */
    input = termline_readline_ctx(ctx->termline_ctx, prompt);

    if (!input) {
      /* EOF (Ctrl+D) */
      printf("\n");
      break;
    }

    /* Skip empty lines */
    if (input[0] == '\0') {
      termline_free(input);
      continue;
    }

    /* Execute line */
    exit_code = mysh_run_string(ctx, input);
    ctx->last_exit_code = exit_code;

    /* Free input */
    termline_free(input);
  }
}

static char **mysh_completion_callback(const char *text, int start, int end,
                                       void *userdata) {
  /* Unused parameters */
  (void)start;
  (void)end;

  ShellContext *ctx = (ShellContext *)userdata;
  if (!ctx || !text)
    return NULL;

  /* Simple completion based on commands and variables */
  size_t text_len = strlen(text);
  size_t max_completions = 32;
  size_t completion_count = 0;

  /* Allocate array for completions */
  char **completions = malloc(sizeof(char *) * (max_completions + 1));
  if (!completions)
    return NULL;

  /* Built-in commands */
  const char *builtins[] = {"cd",   "pwd", "exit",  "export",   "unset",
                            "echo", "set", "alias", "unalias",  "source",
                            "jobs", "fg",  "bg",    "if",       "then",
                            "else", "fi",  "while", "until",    "do",
                            "done", "for", "in",    "function", NULL};

  /* Add matching builtins */
  for (int i = 0; builtins[i] && completion_count < max_completions; i++) {
    if (strncmp(builtins[i], text, text_len) == 0) {
      completions[completion_count++] = strdup(builtins[i]);
    }
  }

  /* Add matching variables */
  EnvScope *scope = ctx->current_scope;
  while (scope && completion_count < max_completions) {
    pthread_mutex_lock(&scope->mutex);

    for (size_t i = 0;
         i < scope->var_count && completion_count < max_completions; i++) {
      if (strncmp(scope->variables[i]->name, text, text_len) == 0) {
        completions[completion_count++] = strdup(scope->variables[i]->name);
      }
    }

    pthread_mutex_unlock(&scope->mutex);
    scope = scope->parent;
  }

  /* Add matching functions */
  pthread_mutex_lock(&ctx->mutex);
  for (size_t i = 0;
       i < ctx->function_count && completion_count < max_completions; i++) {
    if (strncmp(ctx->functions[i]->name, text, text_len) == 0) {
      completions[completion_count++] = strdup(ctx->functions[i]->name);
    }
  }
  pthread_mutex_unlock(&ctx->mutex);

  /* Null-terminate the list */
  completions[completion_count] = NULL;

  /* If no completions, free the array */
  if (completion_count == 0) {
    free(completions);
    return NULL;
  }

  return completions;
}

static void mysh_initialize_termline(ShellContext *ctx) {
  if (!ctx)
    return;

  /* Create termline context */
  ctx->termline_ctx = termline_context_create();

  /* Initialize history */
  ctx->history = termline_history_create(MAX_HISTORY);
  termline_history_set_ctx(ctx->termline_ctx, ctx->history);

  /* Load history from file if exists */
  char history_path[MAX_PATH_LENGTH];
  const char *home = getenv("HOME");
  if (home) {
    snprintf(history_path, MAX_PATH_LENGTH, "%s/.myshell_history", home);
    termline_history_load(ctx->history, history_path);
  }

  /* Set up completion */
  termline_set_completion_callback(ctx->termline_ctx, mysh_completion_callback,
                                   ctx);
}

static void mysh_shutdown_termline(ShellContext *ctx) {
  if (!ctx || !ctx->termline_ctx)
    return;

  /* Save history to file */
  if (ctx->history) {
    char history_path[MAX_PATH_LENGTH];
    const char *home = getenv("HOME");
    if (home) {
      snprintf(history_path, MAX_PATH_LENGTH, "%s/.myshell_history", home);
      termline_history_save(ctx->history, history_path);
    }
  }

  /* Destroy termline context */
  termline_context_destroy(ctx->termline_ctx);
  ctx->termline_ctx = NULL;
  ctx->history = NULL; /* Already freed by termline_context_destroy */
}

/*
 * Public API Functions
 */

ShellContext *mysh_init() {
  ShellContext *ctx = mysh_create_context();
  if (!ctx)
    return NULL;

  /* Initialize environment */
  char cwd[MAX_PATH_LENGTH];
  if (getcwd(cwd, MAX_PATH_LENGTH) != NULL) {
    mysh_set_variable(ctx, "PWD", cwd);
  } else {
    mysh_set_variable(ctx, "PWD", "/");
  }

  /* Set up basic environment variables */
  mysh_set_variable(ctx, "MYSHELL", "1");

  const char *home = getenv("HOME");
  if (home) {
    mysh_set_variable(ctx, "HOME", home);
  }

  const char *user = getenv("USER");
  if (user) {
    mysh_set_variable(ctx, "USER", user);
  }

  /* Set initial status */
  mysh_set_variable(ctx, "?", "0");

  return ctx;
}

void mysh_cleanup(ShellContext *ctx) {
  if (!ctx)
    return;

  /* Clean up resources */
  mysh_destroy_context(ctx);
}

int mysh_run_string(ShellContext *ctx, const char *input) {
  if (!ctx || !input)
    return 1;

  /* Reset context state */
  mysh_reset_context(ctx);

  /* Initialize lexer with input */
  mysh_init_lexer(ctx, input);

  /* Parse input */
  Node *ast = mysh_parse(ctx);
  if (!ast) {
    return MYSH_ERROR_SYNTAX;
  }

  /* Execute AST */
  int result = mysh_execute(ctx, ast);

  /* Store exit code */
  ctx->last_exit_code = result;

  /* Set $? variable */
  char exit_code_str[16];
  snprintf(exit_code_str, sizeof(exit_code_str), "%d", result);
  mysh_set_variable(ctx, "?", exit_code_str);

  return result;
}

int mysh_run_file(ShellContext *ctx, const char *filename) {
  if (!ctx || !filename)
    return 1;

  /* Open file */
  FILE *file = fopen(filename, "r");
  if (!file) {
    perror(filename);
    return MYSH_ERROR_IO;
  }

  /* Read file contents */
  char *buffer = NULL;
  size_t file_size = 0;

  /* Get file size */
  fseek(file, 0, SEEK_END);
  file_size = ftell(file);
  fseek(file, 0, SEEK_SET);

  /* Allocate buffer */
  buffer = mysh_malloc(file_size + 1);
  if (!buffer) {
    fclose(file);
    return MYSH_ERROR_MEMORY;
  }

  /* Read file */
  size_t bytes_read = fread(buffer, 1, file_size, file);
  if (bytes_read < file_size && ferror(file)) {
    perror(filename);
    fclose(file);
    mysh_free(buffer);
    return MYSH_ERROR_IO;
  }

  buffer[bytes_read] = '\0';
  fclose(file);

  /* Execute file contents */
  int result = mysh_run_string(ctx, buffer);

  /* Clean up */
  mysh_free(buffer);

  return result;
}

int mysh_run_interactive(ShellContext *ctx) {
  if (!ctx)
    return 1;

  /* Run interactive shell */
  mysh_interactive_loop(ctx);

  return ctx->last_exit_code;
}

void mysh_set_var(ShellContext *ctx, const char *name, const char *value) {
  if (!ctx || !name)
    return;

  mysh_set_variable(ctx, name, value);
}

char *mysh_get_var(ShellContext *ctx, const char *name) {
  if (!ctx || !name)
    return NULL;

  Variable *var = mysh_get_variable(ctx, name);
  if (var) {
    return mysh_strdup(var->value);
  }

  return NULL;
}

void mysh_register_function(ShellContext *ctx, const char *name,
                            int (*func)(ShellContext *, int, char **)) {
  if (!ctx || !name || !func)
    return;

  /* Not implemented - requires custom function dispatch */
}

/*
 * Main Function (for standalone use)
 */

int main(int argc, char **argv) {
  ShellContext *ctx = mysh_init();
  if (!ctx) {
    fprintf(stderr, "Failed to initialize shell\n");
    return 1;
  }

  int result = 0;

  if (argc > 1) {
    /* Run script from file */
    result = mysh_run_file(ctx, argv[1]);
  } else {
    /* Run interactive shell */
    result = mysh_run_interactive(ctx);
  }

  mysh_cleanup(ctx);
  return result;
}
