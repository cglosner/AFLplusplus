/*
    LCOV tracefile to AFL bitmap

    This is a best effort conversion from an LCOV tracefile to an
    AFL bitmap file. TODO: Create a perfect line to edge mapping for
    coverage information

    The original push for this effor was for using AFL with Simics and UEFI,
    but it can be extended to any software that can produce a LCOV tracefile
    and not an AFL bitmap.

    There is the ability to read in existing LCOV information via a -lcov
    option, similar to the -B option that already exists in current implementation.

    Current Limitations:
     - The line numbers are based off of each file not the total document, so 
       there may be multiple line numbers that correspond to different files
       causing skewed coverage.
*/
#include "afl-fuzz.h"
#include "lcov_coverage.h"
#include <limits.h> 

void get_coverage(afl_forkserver_t *fsrv, u8 *map)
{
    //should take an input of the trace_bit and return the updated
    //trace_bit
    u8 *fname = "";
    //It should read the lcov tracefile and increase a random bit
    //according to the line location
    // fname should be the lcov file name
    FILE *fp = fopen(fname, "r");
    char * line = NULL;
    size_t len = 0;
    u32 msize = (fsrv->map_size >> 2);
    ssize_t read;
    if (fp == NULL) { PFATAL("Unable to open '%s'", fname); }
    
    //since it is best effort it can be some random pattern
    //maybe just the total map size xored with the line number
    //or something like that
    int count = 0;
    int line_number = 0;
    while ((read = getline(&line, &len, fp)) != -1) {
        if(line[0] == 'D')
        {
          int end = 0;
          for(int i = 3; i < read; i++)
          {
            if(line[i] == ',')
            {
              end = i;
              count = atoi(line[i+1]);
              break;
            }
          }
          char* str = malloc(i-3);
          for(int j = 0; j < (end-3); j++)
          {
            str[j] = line[j+3];
          }

          line_number = atoi(str);
          if(str)
            free(str);
          count[msize^line_number] += count;
        }
    }

    if (line)
        free(line);
    
    // fname will be hardcoded to whatever I output from simics
    // can somewhat be based off of read_coverage, except
    // it needs to update and not completely rewrite.
    fclose(fp);
}

/*

void read_coverage(u8 *fname, u8 *map, size_t len)
{
  s32 fd = open(fname, O_RDONLY);

  if (fd < 0) { PFATAL("Unable to open '%s'", fname); }

  ck_read(fd, map, len, fname);

  close(fd);
}

#define mod_read(fd, buf, len, fn)                                \
{                                                                 \
  do {                                                            \
    s32 _len = (s32)(len);                                        \
    s32 _res = read(fd, buf, _len);                               \
    if (_res != _len) RPFATAL(_res, "Short read from %s", fn);    \
  } while (0)                                                     \
}                                                                 \

void simplify_trace(afl_state_t *afl, u8 *bytes) {

  u32 *mem = (u32 *)bytes;
  u32  i = (afl->fsrv.map_size >> 2);

  while (i--) {

    if (unlikely(*mem)) {

      u8 *mem8 = (u8 *)mem;

      mem8[0] = simplify_lookup[mem8[0]];
      mem8[1] = simplify_lookup[mem8[1]];
      mem8[2] = simplify_lookup[mem8[2]];
      mem8[3] = simplify_lookup[mem8[3]];

    } else

      *mem = 0x01010101;

    mem++;

  }

}
*/