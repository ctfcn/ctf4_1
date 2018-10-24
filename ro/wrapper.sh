#!/bin/bash

cd /opt/ctf/gdps/rw

if [[ "i386" == "i386" ]] || [[ "x86_64" == "i386" ]] ; then
  ../ro/gdps 2>/dev/null
else
  qemu-i386 ../ro/gdps 2>/dev/null
fi