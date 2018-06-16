#
# (C) Copyright 2014
# Christophe Vu-Brugier <cvubrugier@fastmail.fm>
#
# SPDX-License-Identifier:	GPL-2.0+
#

include_directories("../src")

add_executable(test-isns-fuzzing
  test-isns-fuzzing.c
  ../src/configfs.c
  ../src/isns.c
  ../src/isns_proto.c
  ../src/itimer.c
  ../src/log.c)
set_property(TARGET test-isns-fuzzing PROPERTY C_STANDARD 99)
target_link_libraries(test-isns-fuzzing
  ccan)
