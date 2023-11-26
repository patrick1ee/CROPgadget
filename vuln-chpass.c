#include <stdio.h>
#include <stdbool.h>
#include <string.h>

bool check_password(char *password) {
  char buffer[15];
  char solution[15] = "DPNTN115:JTGVO"; 
  int result;

  strcpy(buffer, password);
  for (size_t i = 0; i < 14; i++)
    buffer[i] += 1;
  result = strcmp(buffer, solution);

  return result? false : true;
}

int main(int argc, char *argv[]) {
  if (argc > 1)
    printf("You %s!\n", check_password(argv[1])? "win" : "lose");
  return 0;
}