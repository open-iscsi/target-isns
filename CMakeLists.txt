#
# (C) Copyright 2013
# Christophe Vu-Brugier <cvubrugier@yahoo.fr>
#
# SPDX-License-Identifier:	GPL-2.0+
#

project(target-isns "C")

cmake_minimum_required(VERSION 2.8)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Werror -std=c99")

add_subdirectory(src)
install(FILES target-isns.conf DESTINATION /etc/)
