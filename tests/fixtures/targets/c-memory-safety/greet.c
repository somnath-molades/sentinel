#include <stdio.h>
#include <string.h>
#include "greet.h"

/* Vulnerable: unbounded copy of caller data into a fixed buffer. */
void greet_unsafe(const char *name) {
  char buf[16];
  strcpy(buf, name);
  printf("hello %s\n", buf);
}

/* Negative control: bounded copy, always terminated. */
void greet_safe(const char *name) {
  char buf[16];
  strncpy(buf, name, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';
  printf("hello %s\n", buf);
}
