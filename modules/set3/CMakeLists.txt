# Cryptopals
# Problem set 3

add_executable (set3p17 set3p17.c)
target_link_libraries (set3p17 cryptopals -fsanitize=address)

add_executable (set3p18 set3p18.c)
target_link_libraries (set3p18 cryptopals -fsanitize=address)

add_executable (set3p20 set3p20.c)
target_link_libraries (set3p20 cryptopals -fsanitize=address)

add_executable (set3p21 set3p21.c)
target_link_libraries (set3p21 cryptopals -fsanitize=address)
