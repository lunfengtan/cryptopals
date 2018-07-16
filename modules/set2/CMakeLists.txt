# Cryptopals
# Problem set 2

add_executable (set2p9 set2p9.c)
target_link_libraries (set2p9 cryptopals -fsanitize=address)

add_executable (set2p10 set2p10.c)
target_link_libraries (set2p10 cryptopals -fsanitize=address)

add_executable (set2p11 set2p11.c)
target_link_libraries (set2p11 cryptopals -fsanitize=address)

add_executable (set2p12 set2p12.c)
target_link_libraries (set2p12 cryptopals -fsanitize=address)
