#
# (C) Copyright 2013
# Christophe Vu-Brugier <cvubrugier@yahoo.fr>
#
# SPDX-License-Identifier:	GPL-2.0+
#

project(target-isns "C")
set(PROJECT_VERSION "0.3")

cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -std=c99")

add_subdirectory(src)
install(FILES target-isns.conf DESTINATION /etc/)
install(FILES target-isns.8 DESTINATION ${CMAKE_INSTALL_PREFIX}/share/man/man8/)

set(ARCHIVE_NAME ${CMAKE_PROJECT_NAME}-${PROJECT_VERSION})
add_custom_target(dist
  COMMAND git archive --prefix=${ARCHIVE_NAME}/ HEAD
  | xz > ${CMAKE_BINARY_DIR}/${ARCHIVE_NAME}.tar.xz
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
