#
# (C) Copyright 2013
# Christophe Vu-Brugier <cvubrugier@fastmail.fm>
#
# SPDX-License-Identifier:	GPL-2.0+
#

project(target-isns "C")
set(TARGET_ISNS_VERSION "0.6.6")

cmake_minimum_required(VERSION 3.1)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror")

option(SUPPORT_SYSTEMD "Support service control via systemd" OFF)

add_subdirectory(src)
install(FILES target-isns.conf DESTINATION /etc/)
install(FILES target-isns.8 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man8/)
if (SUPPORT_SYSTEMD)
  install(FILES target-isns.service DESTINATION /usr/lib/systemd/system/)
endif (SUPPORT_SYSTEMD)

add_subdirectory(tests)

set(ARCHIVE_NAME ${CMAKE_PROJECT_NAME}-${TARGET_ISNS_VERSION})
add_custom_target(dist
  COMMAND git archive --prefix=${ARCHIVE_NAME}/ HEAD
  | xz > ${CMAKE_BINARY_DIR}/${ARCHIVE_NAME}.tar.xz
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
