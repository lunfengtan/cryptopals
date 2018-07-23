# Cryptopals
# Problem set 2

add_library (kvPairs
                kvPairs.c
            )
target_link_libraries (kvPairs -fsanitize=address)

add_executable (set2p9 set2p9.c)
target_link_libraries (set2p9 cryptopals -fsanitize=address)

add_executable (set2p10 set2p10.c)
target_link_libraries (set2p10 cryptopals -fsanitize=address)

add_executable (set2p11 set2p11.c)
target_link_libraries (set2p11 cryptopals -fsanitize=address)

add_executable (set2p12 set2p12.c)
target_link_libraries (set2p12 cryptopals -fsanitize=address)

add_executable (set2p13 set2p13.c)
target_link_libraries (set2p13 cryptopals kvPairs -fsanitize=address)

add_executable (set2p14 set2p14.c)
target_link_libraries (set2p14 cryptopals -fsanitize=address)

add_executable (set2p15 set2p15.c)
target_link_libraries (set2p15 cryptopals -fsanitize=address)

add_executable (set2p16 set2p16.c)
target_link_libraries (set2p16 cryptopals -fsanitize=address)
