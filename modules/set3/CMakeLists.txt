# Cryptopals
# Problem set 3

add_executable (set3p17 set3p17.c)
target_link_libraries (set3p17 cryptopals -fsanitize=address)
