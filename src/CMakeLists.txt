#
# (C) Copyright 2013
# Christophe Vu-Brugier <cvubrugier@fastmail.fm>
#
# SPDX-License-Identifier:	GPL-2.0+
#

include_directories(".")

configure_file(version.h.in version.h @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_library(ccan STATIC
  ccan/daemonize/daemonize.c
  ccan/list/list.c)

add_executable(target-isns
  configfs.c
  isns.c
  isns_proto.c
  itimer.c
  log.c
  util.c
  target-isns.c)
set_property(TARGET target-isns PROPERTY C_STANDARD 99)
target_link_libraries(target-isns
  ccan)
install(TARGETS target-isns RUNTIME DESTINATION bin)
