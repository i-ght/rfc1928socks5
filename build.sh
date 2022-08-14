CFLAGS="-I./include -I./src -I$HOME/.local/include"
LFLAGS="-L./bin -L$HOME/.local/lib -l:libxpandarray.a"

for dotc_file in ./src/*.c; do
  clang -g -DDEBUG=1 -fPIC -c "$dotc_file" $CFLAGS -o "$dotc_file.o"
done

doto_files=""

for doto_file in ./src/*.c.o; do
  doto_files="${doto_files} ${doto_file}"
done

ar rcs bin/librfc1928socks5.a $doto_files
clang -g -DDEBUG=1 -shared -o bin/librfc1928socks5.so $doto_files $LFLAGS $CFLAGS
 
clang -g -DDEBUG=1 -o bin/program program/program.c -I./include -L./bin -l:librfc1928socks5.a

rm ./src/*.c.o


# install='install'
# uninstall='uninstall'

# case "$1" in
#   "$install")
#     cp bin/librfc1928socks5.so ~/.local/lib/
#     cp bin/librfc1928socks5.a ~/.local/lib/
#     cp include/refqueue.h ~/.local/include
#   ;;
#   "$uninstall")
#     rm ~/.local/lib/librfc1928socks5.so
#     rm ~/.local/lib/librfc1928socks5.a
#     rm ~/.local/include/refqueue.h
#   ;;
#   *)
    
#   ;;
# esac
