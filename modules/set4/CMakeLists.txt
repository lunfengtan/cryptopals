# Cryptopals
# Problem set 4

add_executable (set4p25 set4p25.c)
target_link_libraries (set4p25 cryptopals -fsanitize=address)

add_executable (set4p26 set4p26.c)
target_link_libraries (set4p26 cryptopals -fsanitize=address)
