/*
 * Shows user info from local pwfile.
 *  
 * Usage: userinfo username
 */

#define _XOPEN_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pwdblib.h"   /* include header declarations for pwdblib.c */

/* Define some constants. */
#define USERNAME_SIZE (32)
#define NOUSER (-1)


int print_info(const char *username)
{
  struct pwdb_passwd *p = pwdb_getpwnam(username);
  if (p != NULL) {
	return 0;
  } else {
    return NOUSER;
  }
}

void read_username(char *username)
{
  printf("login: ");
  fgets(username, USERNAME_SIZE, stdin);

  /* remove the newline included by getline() */
  username[strlen(username) - 1] = '\0';
}

void read_password(char *password)
{
  password = getpass("Password: ");
}

int login_screen()
{
  char username[USERNAME_SIZE];
  char *password;
  
  while (1) {
  /* 
    * Write "login: " and read user input. Copies the username to the
    * username variable.
    */
    read_username(username);
    password = getpass("Password: ");

    struct pwdb_passwd *p = pwdb_getpwnam(username);
    if (print_info(username) == NOUSER) return -1;
    char salt[2];
    salt[0] = p->pw_passwd[0];
    salt[1] = p->pw_passwd[1];
    int comp = strcmp(p->pw_passwd, crypt(password, salt));
    
    if (print_info(username) == NOUSER || comp != 0){
      return -1;
    } else {
      printf("User authenticated successfully");
      return 0;
    }
  }
}

int main(int argc, char **argv)
{
  int c = 1;
  while (c != 0) {
    if (c == -1) printf("Unknown user or incorrect password\n");
    c = login_screen();
  }
  return 0;
}
