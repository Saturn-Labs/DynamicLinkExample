project(Library VERSION 1.0.0)
add_library(Library SHARED "source/main.cpp")
target_include_directories(Library PRIVATE "source")