#ifndef COMMON_H
#define COMMON_H

#include <SDL_stdinc.h>

#define ARRAY_LEN(a) (sizeof(a) / sizeof(a[0]))
#define MIN(X,Y) (X) < (Y) ? (X) : (Y)
#define MAX(X,Y) (X) > (Y) ? (X) : (Y)

struct size {
    Uint16 width;
    Uint16 height;
};

struct point {
    Sint32 x;
    Sint32 y;
};

struct position {
    // The video screen size may be different from the real device screen size,
    // so store to which size the absolute position apply, to scale it accordingly.
    struct size screen_size;
    struct point point;
};

#endif
