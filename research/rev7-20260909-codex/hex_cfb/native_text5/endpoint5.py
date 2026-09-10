#!/usr/bin/env python3
"""Registered ASCII plus five UTF-8 punctuation endpoint."""
def transition(state, _unused, value):
    if state == 0:
        if value in (9, 10, 13) or 32 <= value <= 126:
            return 0
        return 1 if value == 0xE2 else None
    if state == 1:
        return 2 if value == 0x80 else None
    if state == 2:
        return 0 if value in (0x93, 0x94, 0x98, 0x99, 0xA6) else None
    raise ValueError("invalid endpoint state")

def accepts(data):
    state=0
    for value in data:
        state=transition(state,0,value)
        if state is None:return False
    return state==0
