#include <stdint.h>
#include <stdio.h>

#define CHARSET_SIZE 62
const char *CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

#define DEPTH 8

#define PASSWD_LEN 0x10
uint32_t fnv1a(uint32_t start, uint8_t *str, uint8_t len)
{
  uint32_t ret;
  uint8_t i;

  if(start)
  {
    ret = start;
  }
  else
  {
    // Vanilla FNV1a seed
    ret = 0x811C9DC5;
  }

  for(i = 0 ; i < len ; i++)
  {
    ret *= 0x1000193;
    ret ^= str[i];
  }

  return ret;
}

uint8_t test_alphanumeric(char c)
{
  if(c >= 0x30 && c <= 0x39)
  {
    return 1;
  }

  if(c >= 0x41 && c <= 0x5A)
  {
    return 1;
  }

  if(c >= 0x61 && c <= 0x7A)
  {
    return 1;
  }

  return 0;
}

// Tries to list all 8-char alphanumeric solutions.
uint8_t recursive_crack(uint32_t fnv1a_seed, char *str, uint8_t depth, int32_t adler32high, int32_t adler32low)
{
  uint8_t i, left;
  uint16_t c;

  left = DEPTH - depth;

  if(adler32high < (((left * (left + 1)) >> 1) * 0x30 + DEPTH) || adler32low < (0x30 * left + 0x1))
  {
    return 0;
  }

  if(adler32high > (((left * (left + 1)) >> 1) * 0x7A + DEPTH) || adler32low > (0x7A * left + 0x1))
  {
    return 0;
  }

  if(left == 2)
  {
    str[depth] = (adler32high - 8) - (adler32low - 1);
    if(!test_alphanumeric(str[depth]))
    {
      return 0;
    }

    str[depth + 1] = (adler32low - 1) - str[depth];
    if(!test_alphanumeric(str[depth + 1]))
    {
      return 0;
    }

    // printf("%s\n", str);

    return (fnv1a(fnv1a_seed, str, DEPTH) == 0x31F009D2);
  }

  for(i = 0 ; i < CHARSET_SIZE ; i++)
  {
    c = CHARSET[i];
    str[depth] = c;
    if(recursive_crack(fnv1a_seed, str, depth + 1, adler32high - (DEPTH - depth) * c, adler32low - c))
    {
      return 1;
    }
  }

  return 0;
}

int main(int argc, char *argv[])
{
  char str[PASSWD_LEN] = {'V', 'e', 'r', 'Y', 'D', 'u', 'm', 'B'};
  recursive_crack(fnv1a(0, str, PASSWD_LEN - DEPTH), &str[PASSWD_LEN - DEPTH], 0, 0xF91, 0x374);
  printf("Solution: %.*s\n", PASSWD_LEN, str);
  return 0;
}
