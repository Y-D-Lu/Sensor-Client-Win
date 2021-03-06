#ifndef CONVERT_H
#define CONVERT_H

#include <SDL_stdinc.h>
#include <SDL_events.h>
#include "control_event.h"

struct complete_mouse_motion_event {
    SDL_MouseMotionEvent *mouse_motion_event;
    struct size screen_size;
};

struct complete_mouse_wheel_event {
    SDL_MouseWheelEvent *mouse_wheel_event;
    struct point position;
};

SDL_bool input_key_from_sdl_to_android(const SDL_KeyboardEvent *from,
                                       struct control_event *to);
SDL_bool mouse_button_from_sdl_to_android(const SDL_MouseButtonEvent *from,
                                          struct size screen_size,
                                          struct control_event *to);

// the video size may be different from the real device size, so we need the size
// to which the absolute position apply, to scale it accordingly
SDL_bool mouse_motion_from_sdl_to_android(const SDL_MouseMotionEvent *from,
                                          struct size screen_size,
                                          struct control_event *to);

// on Android, a scroll event requires the current mouse position
SDL_bool mouse_wheel_from_sdl_to_android(const SDL_MouseWheelEvent *from,
                                         struct position position,
                                         struct control_event *to);

#endif
