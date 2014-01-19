#
# (C) Copyright 2013
# Christophe Vu-Brugier <cvubrugier@yahoo.fr>
#
# SPDX-License-Identifier:	GPL-2.0+
#

include_directories(".")

add_library(ccan STATIC
  ccan/daemonize/daemonize.c
  ccan/list/list.c)

add_executable(target-isns
  configfs.c
  isns.c
  isns_proto.c
  log.c
  util.c
  target-isns.c)
target_link_libraries(target-isns
  ccan)
install(TARGETS target-isns RUNTIME DESTINATION bin)
