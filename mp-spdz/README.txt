Suppose this folder is the application.
Client and MB's inputs are stored under /Player-Data/Input-Px-0, such that x is 0:client 1:MB, respectively

Note that the input is in biginteger format.

To run the program, open your bash at this directory, and 
type: Scripts/yao.sh jason_aes
or
type: Scripts/semi.sh jason_aes

This will execute the interactive protocol using yao-GC or secret sharing with the compiled 'jason_aes' program.


To edit the program, navigate to /Programs/Source/jason_aes.mpc
After editing, navigate back to this directory, and
type: ./compile.py jason_aes -l